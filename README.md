# Jiayi_Wang_Proxy
Proxy Simulator in C with Caching Ability

## Intro
* Established a concurrent web proxy with HTTP operations implemented by threads, and utilized mutex to resolve race
conditions for shared resources through multiple threads.
* Designed a cache library with 1024 ∗ 1024 bits storage implemented by linked list data structure and LRU eviction policy to
assist caching of web requests and responses.
* Further enhanced the robustness of web proxy through error handling in response to malformed client requests and failure of
server responses.

## Note
This repo only contains the implementation without the auxiliary helper functions provided as starter code due to privacy reason.
