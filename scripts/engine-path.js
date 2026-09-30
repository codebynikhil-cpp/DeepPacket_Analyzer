const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const binary = process.platform === 'win32' ? 'PacketInspector.exe' : 'PacketInspector';
const candidates = process.env.DPA_ENGINE_PATH ? [path.resolve(process.env.DPA_ENGINE_PATH)] : [
    path.join(root, 'build', binary),
    path.join(root, 'build', 'Release', binary),
    path.join(root, 'build', 'Debug', binary)
];
module.exports = candidates.find(candidate => fs.existsSync(candidate)) || candidates[0];
