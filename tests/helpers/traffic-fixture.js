// Deterministic, synthetic traffic on documentation-only addresses. These are
// test packets, not a recording of someone's network or an accuracy dataset.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const executable = require('../../scripts/engine-path');
const emptyRules = { blocked_ips:[], blocked_domains:[], blocked_apps:[], blocked_ports:[] };
function checksum(buffer) {
    let sum = 0;
    for (let i = 0; i < buffer.length; i += 2) sum += (buffer[i] << 8) | (buffer[i + 1] || 0);
    while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
    return (~sum) & 0xffff;
}
function tcp(payload, source, destination, flags = 0x18) {
    const header = Buffer.alloc(20);
    header.writeUInt16BE(source, 0); header.writeUInt16BE(destination, 2);
    header.writeUInt32BE(1000, 4); header.writeUInt32BE(2000, 8);
    header[12] = 0x50; header[13] = flags; header.writeUInt16BE(64240, 14);
    return Buffer.concat([header, payload]);
}
function udp(payload, source, destination) {
    const header = Buffer.alloc(8);
    header.writeUInt16BE(source, 0); header.writeUInt16BE(destination, 2); header.writeUInt16BE(payload.length + 8, 4);
    return Buffer.concat([header, payload]);
}
function tls(hostname) {
    const host = Buffer.from(hostname);
    const name = Buffer.concat([Buffer.from([0,0,host.length]),host]);
    const serverNames = Buffer.concat([Buffer.from([0,name.length]),name]);
    const sni = Buffer.concat([Buffer.from([0,0,0,serverNames.length]),serverNames]);
    const body = Buffer.concat([Buffer.from([3,3]),Buffer.alloc(32),Buffer.from([0,0,2,0x13,1,1,0,0,sni.length]),sni]);
    const handshake = Buffer.alloc(4); handshake[0] = 1; handshake.writeUIntBE(body.length,1,3);
    const record = Buffer.alloc(5); record[0] = 22; record.writeUInt16BE(0x0301,1); record.writeUInt16BE(body.length + 4,3);
    return Buffer.concat([record,handshake,body]);
}
function dns(hostname) {
    const labels = hostname.split('.').flatMap(label => [Buffer.from([label.length]),Buffer.from(label)]);
    return Buffer.concat([Buffer.from([0x12,0x34,1,0,0,1,0,0,0,0,0,0]),...labels,Buffer.from([0,0,1,0,1])]);
}
function ipv4(segment, protocol, index, reverse = false) {
    const ethernet = Buffer.from('0200000000020200000000010800','hex');
    const source = Buffer.from([192,0,2,10 + index % 3]);
    const destination = Buffer.from([198,51,100,20 + index % 11]);
    const ip = Buffer.alloc(20);
    ip[0] = 0x45; ip.writeUInt16BE(20 + segment.length,2); ip.writeUInt16BE(index % 65536,4);
    ip[8] = 64; ip[9] = protocol;
    (reverse ? destination : source).copy(ip,12); (reverse ? source : destination).copy(ip,16);
    ip.writeUInt16BE(checksum(ip),10);
    if (protocol === 6 || protocol === 17) {
        const pseudo = Buffer.concat([ip.subarray(12,20),Buffer.from([0,protocol,segment.length >> 8,segment.length & 255]),segment]);
        segment.writeUInt16BE(checksum(pseudo) || 0xffff, protocol === 6 ? 16 : 6);
    } else if (protocol === 1) segment.writeUInt16BE(checksum(segment),2);
    return Buffer.concat([ethernet,ip,segment]);
}
function createTrafficPcap(count = 900) {
    const header = Buffer.alloc(24);
    header.writeUInt32LE(0xa1b2c3d4,0); header.writeUInt16LE(2,4); header.writeUInt16LE(4,6);
    header.writeUInt32LE(65535,16); header.writeUInt32LE(1,20);
    const records = [header];
    // A varied but deterministic timeline, with multiple flows and packet sizes.
    const start = 1790726400;
    let microseconds = 0;
    for (let i = 0; i < count; i++) {
        let frame;
        const sourcePort = 49000 + i % 16;
        switch (i % 7) {
            case 0: frame = ipv4(tcp(Buffer.from(`GET /docs/${i % 8} HTTP/1.1\r\nHost: github.com\r\n\r\n`),sourcePort,80),6,i); break;
            case 1: frame = ipv4(tcp(tls('example.com'),sourcePort,443),6,i); break;
            case 2: frame = ipv4(udp(dns('example.com'),sourcePort,53),17,i); break;
            case 3: frame = ipv4(tcp(Buffer.alloc(900 + i % 400,0x41),443,sourcePort),6,i,true); break;
            case 4: frame = ipv4(udp(Buffer.alloc(80 + i % 300,0x32),sourcePort,5353),17,i); break;
            case 5: frame = ipv4(Buffer.concat([Buffer.from([8,0,0,0,0,1,0,1]),Buffer.alloc(32)]),1,i); break;
            default: frame = ipv4(tcp(Buffer.alloc(0),sourcePort,443,0x10),6,i); break;
        }
        microseconds += 25000 + Math.round((1 + Math.sin(i / 35)) * 55000);
        const record = Buffer.alloc(16);
        record.writeUInt32LE(start + Math.floor(microseconds / 1e6),0); record.writeUInt32LE(microseconds % 1e6,4);
        record.writeUInt32LE(frame.length,8); record.writeUInt32LE(frame.length,12);
        records.push(record,frame);
    }
    return Buffer.concat(records);
}
function analyzeFixture(directory, count = 900) {
    if (!fs.existsSync(executable)) throw new Error('Build PacketInspector before generating the fixture');
    fs.mkdirSync(directory,{recursive:true});
    const input = path.join(directory,'synthetic-demo.pcap');
    fs.writeFileSync(input,createTrafficPcap(count));
    fs.writeFileSync(path.join(directory,'rules.json'),JSON.stringify(emptyRules));
    fs.writeFileSync(path.join(directory,'critical_websites.json'),JSON.stringify({websites:[]}));
    const result = spawnSync(executable,['--pcap',input],{cwd:directory,encoding:'utf8',timeout:60000,windowsHide:true});
    if (result.status !== 0) throw new Error(result.stderr || result.stdout || `Exit ${result.status}`);
    return JSON.parse(fs.readFileSync(path.join(directory,'output.json'),'utf8'));
}
module.exports = { createTrafficPcap, analyzeFixture, executable, emptyRules };
