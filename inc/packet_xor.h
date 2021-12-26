/********************************************************
 * Description : packet xor divide and unify
 * Author      : yanrk
 * Email       : yanrkchina@163.com
 * Version     : 1.0
 * History     :
 * Copyright(C): 2021-2022
 ********************************************************/

#ifndef PACKET_XOR_H
#define PACKET_XOR_H


#ifdef _MSC_VER
    #define PACKET_XOR_CDECL            __cdecl
    #ifdef EXPORT_PACKET_XOR_DLL
        #define PACKET_XOR_TYPE         __declspec(dllexport)
    #else
        #ifdef USE_PACKET_XOR_DLL
            #define PACKET_XOR_TYPE     __declspec(dllimport)
        #else
            #define PACKET_XOR_TYPE
        #endif // USE_PACKET_XOR_DLL
    #endif // EXPORT_PACKET_XOR_DLL
#else
    #define PACKET_XOR_CDECL
    #define PACKET_XOR_TYPE
#endif // _MSC_VER

#include <cstdint>
#include <list>
#include <vector>

class PacketXorDividerImpl;
class PacketXorUnifierImpl;

typedef void (*encode_callback_t)(void * user_data, const uint8_t * dst_data, uint32_t dst_size);
typedef void (*decode_callback_t)(void * user_data, const uint8_t * dst_data, uint32_t dst_size);

class PACKET_XOR_TYPE PacketXorDivider
{
public:
    PacketXorDivider();
    PacketXorDivider(const PacketXorDivider &) = delete;
    PacketXorDivider(PacketXorDivider &&) = delete;
    PacketXorDivider & operator = (const PacketXorDivider &) = delete;
    PacketXorDivider & operator = (PacketXorDivider &&) = delete;
    ~PacketXorDivider();

public:
    bool init(uint32_t max_block_size, bool use_xor);
    void exit();

public:
    bool encode(const uint8_t * src_data, uint32_t src_size, std::list<std::vector<uint8_t>> & dst_list);
    bool encode(const uint8_t * src_data, uint32_t src_size, encode_callback_t * encode_callback, void * user_data);

public:
    void reset();

private:
    PacketXorDividerImpl  * m_divider;
};

class PACKET_XOR_TYPE PacketXorUnifier
{
public:
    PacketXorUnifier();
    PacketXorUnifier(const PacketXorUnifier &) = delete;
    PacketXorUnifier(PacketXorUnifier &&) = delete;
    PacketXorUnifier & operator = (const PacketXorUnifier &) = delete;
    PacketXorUnifier & operator = (PacketXorUnifier &&) = delete;
    ~PacketXorUnifier();

public:
    bool init(uint32_t expire_millisecond = 15, double fault_tolerance_rate = 0.0);
    void exit();

public:
    bool decode(const uint8_t * src_data, uint32_t src_size, std::list<std::vector<uint8_t>> & dst_list);
    bool decode(const uint8_t * src_data, uint32_t src_size, decode_callback_t * decode_callback, void * user_data);

public:
    static bool recognizable(const uint8_t * src_data, uint32_t src_size);

public:
    void reset();

private:
    PacketXorUnifierImpl  * m_unifier;
};


#endif // PACKET_XOR_H
