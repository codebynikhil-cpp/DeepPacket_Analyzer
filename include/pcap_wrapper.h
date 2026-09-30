#ifndef PCAP_WRAPPER_H
#define PCAP_WRAPPER_H

#include <cstdint>
#include <string>
#include <vector>
#include <iostream>

#if defined(__has_include)
  #if __has_include(<pcap.h>)
    #define HAVE_NATIVE_PCAP_H 1
  #endif
#endif

#ifdef HAVE_NATIVE_PCAP_H
  #include <pcap.h>
#else
  // Native header not found - provide portable fallback definitions for Npcap / libpcap DLL loading on Windows/Linux
  #if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
    #include <windows.h>
  #else
    #include <dlfcn.h>
  #endif

  #ifndef PCAP_ERRBUF_SIZE
    #define PCAP_ERRBUF_SIZE 256
  #endif

  struct pcap_addr {
      struct pcap_addr *next;
      void *addr;
      void *netmask;
      void *broadaddr;
      void *dstaddr;
  };

  struct pcap_if {
      struct pcap_if *next;
      char *name;
      char *description;
      struct pcap_addr *addresses;
      uint32_t flags;
  };

  typedef struct pcap_if pcap_if_t;

  struct pcap_pkthdr {
      struct {
          long tv_sec;
          long tv_usec;
      } ts;
      uint32_t caplen;
      uint32_t len;
  };

  struct pcap_stat {
      uint32_t ps_recv;
      uint32_t ps_drop;
      uint32_t ps_ifdrop;
  };

  typedef void pcap_t;

  // Dynamic loader helper class
  class PcapLoader {
  public:
      typedef int (*fn_pcap_findalldevs)(pcap_if_t **, char *);
      typedef void (*fn_pcap_freealldevs)(pcap_if_t *);
      typedef pcap_t* (*fn_pcap_open_live)(const char *, int, int, int, char *);
      typedef void (*fn_pcap_close)(pcap_t *);
      typedef int (*fn_pcap_next_ex)(pcap_t *, struct pcap_pkthdr **, const unsigned char **);
      typedef void (*fn_pcap_breakloop)(pcap_t *);
      typedef int (*fn_pcap_stats)(pcap_t *, struct pcap_stat *);
      typedef int (*fn_pcap_datalink)(pcap_t *);

      static bool init() {
          static bool initialized = false;
          static bool available = false;
          if (initialized) return available;
          initialized = true;

#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
          HMODULE module = LoadLibraryA("wpcap.dll");
          if (!module) module = LoadLibraryA("npcap\\wpcap.dll");
          if (!module) module = LoadLibraryA("C:\\Windows\\System32\\Npcap\\wpcap.dll");
          if (!module) return false;

          p_findalldevs = (fn_pcap_findalldevs)GetProcAddress(module, "pcap_findalldevs");
          p_freealldevs = (fn_pcap_freealldevs)GetProcAddress(module, "pcap_freealldevs");
          p_open_live   = (fn_pcap_open_live)GetProcAddress(module, "pcap_open_live");
          p_close       = (fn_pcap_close)GetProcAddress(module, "pcap_close");
          p_next_ex     = (fn_pcap_next_ex)GetProcAddress(module, "pcap_next_ex");
          p_breakloop   = (fn_pcap_breakloop)GetProcAddress(module, "pcap_breakloop");
          p_stats       = (fn_pcap_stats)GetProcAddress(module, "pcap_stats");
          p_datalink    = (fn_pcap_datalink)GetProcAddress(module, "pcap_datalink");
#else
          void* module = dlopen("libpcap.so", RTLD_LAZY);
          if (!module) module = dlopen("libpcap.so.1", RTLD_LAZY);
          if (!module) module = dlopen("libpcap.so.0.8", RTLD_LAZY);
          if (!module) return false;

          p_findalldevs = (fn_pcap_findalldevs)dlsym(module, "pcap_findalldevs");
          p_freealldevs = (fn_pcap_freealldevs)dlsym(module, "pcap_freealldevs");
          p_open_live   = (fn_pcap_open_live)dlsym(module, "pcap_open_live");
          p_close       = (fn_pcap_close)dlsym(module, "pcap_close");
          p_next_ex     = (fn_pcap_next_ex)dlsym(module, "pcap_next_ex");
          p_breakloop   = (fn_pcap_breakloop)dlsym(module, "pcap_breakloop");
          p_stats       = (fn_pcap_stats)dlsym(module, "pcap_stats");
          p_datalink    = (fn_pcap_datalink)dlsym(module, "pcap_datalink");
#endif
          available = (p_findalldevs && p_freealldevs && p_open_live && p_close && p_next_ex && p_datalink);
          return available;
      }

      static fn_pcap_findalldevs p_findalldevs;
      static fn_pcap_freealldevs p_freealldevs;
      static fn_pcap_open_live   p_open_live;
      static fn_pcap_close       p_close;
      static fn_pcap_next_ex     p_next_ex;
      static fn_pcap_breakloop   p_breakloop;
      static fn_pcap_stats       p_stats;
      static fn_pcap_datalink    p_datalink;
  };

  #define pcap_findalldevs PcapLoader::p_findalldevs
  #define pcap_freealldevs PcapLoader::p_freealldevs
  #define pcap_open_live   PcapLoader::p_open_live
  #define pcap_close       PcapLoader::p_close
  #define pcap_next_ex     PcapLoader::p_next_ex
  #define pcap_breakloop   PcapLoader::p_breakloop
  #define pcap_stats       PcapLoader::p_stats
  #define pcap_datalink    PcapLoader::p_datalink
#endif

#endif // PCAP_WRAPPER_H
