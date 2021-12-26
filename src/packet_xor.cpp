/********************************************************
 * Description : packet xor divide and unify
 * Author      : yanrk
 * Email       : yanrkchina@163.com
 * Version     : 1.0
 * History     :
 * Copyright(C): 2021-2022
 ********************************************************/

#ifdef _MSC_VER
    #include <windows.h>
#else
    #include <sys/time.h>
#endif // _MSC_VER

#include <ctime>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <map>
#include <list>
#include <vector>
#include <algorithm>

#include "packet_xor.h"

const uint8_t s_protocol_seq = 0xe9;
const uint8_t s_protocol_xor = 0xea;

static void byte_order_convert(void * obj, size_t size)
{
    assert(nullptr != obj);

    static union
    {
        unsigned short us;
        unsigned char  uc[sizeof(unsigned short)];
    } un;
    un.us = 0x0001;

    if (0x01 == un.uc[0])
    {
        unsigned char * bytes = static_cast<unsigned char *>(obj);
        for (size_t i = 0; i < size / 2; ++i)
        {
            unsigned char temp = bytes[i];
            bytes[i] = bytes[size - 1 - i];
            bytes[size - 1 - i] = temp;
        }
    }
}

static void host_to_net(void * obj, size_t size)
{
    byte_order_convert(obj, size);
}

static void net_to_host(void * obj, size_t size)
{
    byte_order_convert(obj, size);
}

#pragma pack(push, 1)

struct block_t
{
    uint64_t                            group_index;
    uint8_t                             protocol_id;
    uint8_t                             block_idx_h;
    uint16_t                            block_idx_l;
    uint32_t                            block_count;
    uint32_t                            block_bytes;
    uint32_t                            block_pos;
    uint32_t                            group_bytes;

    void encode()
    {
        host_to_net(&group_index, sizeof(group_index));
        host_to_net(&protocol_id, sizeof(protocol_id));
        host_to_net(&block_idx_h, sizeof(block_idx_h));
        host_to_net(&block_idx_l, sizeof(block_idx_l));
        host_to_net(&block_count, sizeof(block_count));
        host_to_net(&block_bytes, sizeof(block_bytes));
        host_to_net(&block_pos, sizeof(block_pos));
        host_to_net(&group_bytes, sizeof(group_bytes));
    }

    void decode()
    {
        net_to_host(&group_index, sizeof(group_index));
        net_to_host(&protocol_id, sizeof(protocol_id));
        net_to_host(&block_idx_h, sizeof(block_idx_h));
        net_to_host(&block_idx_l, sizeof(block_idx_l));
        net_to_host(&block_count, sizeof(block_count));
        net_to_host(&block_bytes, sizeof(block_bytes));
        net_to_host(&block_pos, sizeof(block_pos));
        net_to_host(&group_bytes, sizeof(group_bytes));
    }
};

#pragma pack(pop)

struct group_head_t
{
    uint64_t                            group_index;
    uint32_t                            group_bytes;
    uint32_t                            need_block_count;
    uint32_t                            recv_block_count;

    group_head_t()
        : group_index(0)
        , group_bytes(0)
        , need_block_count(0)
        , recv_block_count(0)
    {

    }
};

struct group_body_t
{
    std::vector<uint8_t>                seq_block_bitmap;
    std::vector<uint8_t>                xor_block_bitmap;
    std::vector<uint8_t>                group_data;
};

struct group_t
{
    group_head_t                        head;
    group_body_t                        body;
};

struct decode_timer_t
{
    uint64_t                            group_index;
    uint32_t                            decode_seconds;
    uint32_t                            decode_microseconds;
};

struct groups_t
{
    uint64_t                            min_group_index;
    uint64_t                            new_group_index;
    std::map<uint64_t, group_t>         group_items;
    std::list<decode_timer_t>           decode_timer_list;

    groups_t()
        : min_group_index(0)
        , new_group_index(0)
        , group_items()
        , decode_timer_list()
    {

    }

    void reset()
    {
        min_group_index = 0;
        new_group_index = 0;
        group_items.clear();
        decode_timer_list.clear();
    }
};

static void get_current_time(uint32_t & seconds, uint32_t & microseconds)
{
#ifdef _MSC_VER
    SYSTEMTIME sys_now = { 0x0 };
    GetLocalTime(&sys_now);
    seconds = static_cast<uint32_t>(time(nullptr));
    microseconds = static_cast<uint32_t>(sys_now.wMilliseconds * 1000);
#else
    struct timeval tv_now = { 0x0 };
    gettimeofday(&tv_now, nullptr);
    seconds = static_cast<uint32_t>(tv_now.tv_sec);
    microseconds = static_cast<uint32_t>(tv_now.tv_usec);
#endif // _MSC_VER
}

static void fill_xor_data(uint8_t * xor_data, const uint8_t * prev_data, const uint8_t * next_data, uint32_t data_size)
{
    for (uint32_t index = 0; index < data_size; ++index)
    {
        xor_data[index] = prev_data[index] ^ next_data[index];
    }
}

static bool packet_divide(const uint8_t * src_data, uint32_t src_size, uint32_t max_block_size, bool use_xor, uint64_t & group_index, std::list<std::vector<uint8_t>> & dst_list, encode_callback_t * encode_callback, void * user_data)
{
    if (nullptr == src_data || 0 == src_size)
    {
        return (false);
    }

    if (max_block_size <= sizeof(block_t))
    {
        return (false);
    }

    uint32_t max_block_bytes = static_cast<uint32_t>(max_block_size - sizeof(block_t));
    uint32_t group_bytes = src_size;
    uint32_t block_pos = 0;
    uint32_t block_index = 0;
    uint32_t block_count = (group_bytes + max_block_bytes - 1) / max_block_bytes;
    if (block_count > 0x00FFFFFF)
    {
        return (false);
    }

    std::vector<uint8_t> * pre_buffer_ptr = nullptr;
    block_t xor_block = { 0x0 };

    while (0 != src_size)
    {
        uint32_t block_bytes = std::min<uint32_t>(max_block_bytes, src_size);

        block_t seq_block = { 0x0 };
        seq_block.group_index = group_index;
        seq_block.group_bytes = group_bytes;
        seq_block.block_pos = block_pos;
        seq_block.protocol_id = s_protocol_seq;
        seq_block.block_idx_h = static_cast<uint8_t>((block_index >> 16) & 0x00FF);
        seq_block.block_idx_l = static_cast<uint16_t>(block_index & 0xFFFF);
        seq_block.block_count = block_count;
        seq_block.block_bytes = block_bytes;

        xor_block = seq_block;
        xor_block.protocol_id = s_protocol_xor;

        seq_block.encode();
        xor_block.encode();

        std::vector<uint8_t> seq_buffer(static_cast<uint32_t>(sizeof(seq_block) + max_block_bytes), 0x0);
        memcpy(&seq_buffer[0], &seq_block, sizeof(seq_block));
        memcpy(&seq_buffer[sizeof(seq_block)], src_data, block_bytes);

        if (use_xor)
        {
            if (1 == block_count)
            {
                if (nullptr != encode_callback)
                {
                    (*encode_callback)(user_data, &seq_buffer[0], static_cast<uint32_t>(seq_buffer.size()));
                }
                dst_list.push_back(seq_buffer);
                if (nullptr != encode_callback)
                {
                    (*encode_callback)(user_data, &seq_buffer[0], static_cast<uint32_t>(seq_buffer.size()));
                }
                dst_list.emplace_back(std::move(seq_buffer));
            }
            else if (0 == block_index)
            {
                if (nullptr != encode_callback)
                {
                    (*encode_callback)(user_data, &seq_buffer[0], static_cast<uint32_t>(seq_buffer.size()));
                }
                dst_list.emplace_back(std::move(seq_buffer));
                pre_buffer_ptr = &dst_list.back();
            }
            else
            {
                std::vector<uint8_t> & pre_buffer = *pre_buffer_ptr;
                std::vector<uint8_t> xor_buffer(static_cast<uint32_t>(sizeof(xor_block) + max_block_bytes), 0x0);
                memcpy(&xor_buffer[0], &xor_block, sizeof(xor_block));
                fill_xor_data(&xor_buffer[sizeof(xor_block)], &pre_buffer[sizeof(seq_block)], &seq_buffer[sizeof(seq_block)], max_block_bytes);
                if (nullptr != encode_callback)
                {
                    (*encode_callback)(user_data, &seq_buffer[0], static_cast<uint32_t>(seq_buffer.size()));
                }
                dst_list.emplace_back(std::move(seq_buffer));
                pre_buffer_ptr = &dst_list.back();
                if (nullptr != encode_callback)
                {
                    (*encode_callback)(user_data, &xor_buffer[0], static_cast<uint32_t>(xor_buffer.size()));
                }
                dst_list.emplace_back(std::move(xor_buffer));
            }
        }
        else
        {
            if (nullptr != encode_callback)
            {
                (*encode_callback)(user_data, &seq_buffer[0], static_cast<uint32_t>(seq_buffer.size()));
            }
            dst_list.emplace_back(std::move(seq_buffer));
        }

        src_data += block_bytes;
        src_size -= block_bytes;
        block_pos += block_bytes;

        ++block_index;
    }

    ++group_index;

    return (true);
}

static bool insert_group_block(group_t & group, block_t & cur_block, uint32_t cur_block_index, const uint8_t * data, uint32_t size)
{
    group_head_t & group_head = group.head;
    group_body_t & group_body = group.body;
    uint32_t pre_block_index = cur_block_index - 1;
    uint32_t nex_block_index = cur_block_index + 1;

    if (s_protocol_seq == cur_block.protocol_id)
    {
        if (group_body.seq_block_bitmap[cur_block_index >> 3] & (1 << (cur_block_index & 7)))
        {
            return (false);
        }

        if (cur_block_index > 0)
        {
            if (group_body.xor_block_bitmap[cur_block_index >> 3] & (1 << (cur_block_index & 7)))
            {
                group_body.xor_block_bitmap[cur_block_index >> 3] &= ~static_cast<uint8_t>(1 << (cur_block_index & 7));
                std::vector<uint8_t> pre_buffer(size, 0x0);
                fill_xor_data(&pre_buffer[0], &group_body.group_data[cur_block.block_pos], data, size);
                block_t pre_block = cur_block;
                pre_block.protocol_id = s_protocol_seq;
                pre_block.block_bytes = size;
                pre_block.block_pos -= size;
                insert_group_block(group, pre_block, pre_block_index, &pre_buffer[0], size);
            }
        }

        group_head.recv_block_count += 1;
        group_body.xor_block_bitmap[cur_block_index >> 3] &= ~static_cast<uint8_t>(1 << (cur_block_index & 7));
        group_body.seq_block_bitmap[cur_block_index >> 3] |= (1 << (cur_block_index & 7));

        if (cur_block_index + 1 == cur_block.block_count)
        {
            group_body.group_data.resize(std::max<std::size_t>(group_body.group_data.size(), cur_block.block_pos + size), 0x0);
        }
        memcpy(&group_body.group_data[cur_block.block_pos], data, size);

        if (nex_block_index < cur_block.block_count)
        {
            if (group_body.xor_block_bitmap[nex_block_index >> 3] & (1 << (nex_block_index & 7)))
            {
                group_body.xor_block_bitmap[nex_block_index >> 3] &= ~static_cast<uint8_t>(1 << (nex_block_index & 7));
                std::vector<uint8_t> nex_buffer(size, 0x0);
                fill_xor_data(&nex_buffer[0], &group_body.group_data[cur_block.block_pos + size], data, size);
                block_t nex_block = cur_block;
                nex_block.protocol_id = s_protocol_seq;
                nex_block.block_bytes = size;
                nex_block.block_pos += size;
                insert_group_block(group, nex_block, nex_block_index, &nex_buffer[0], size);
            }
        }
    }
    else
    {
        if (0 == cur_block_index)
        {
            return (false);
        }

        if (group_body.xor_block_bitmap[cur_block_index >> 3] & (1 << (cur_block_index & 7)))
        {
            return (false);
        }

        if (group_body.seq_block_bitmap[cur_block_index >> 3] & (1 << (cur_block_index & 7)))
        {
            if (group_body.seq_block_bitmap[pre_block_index >> 3] & (1 << (pre_block_index & 7)))
            {
                return (false);
            }
            else
            {
                std::vector<uint8_t> pre_buffer(size, 0x0);
                fill_xor_data(&pre_buffer[0], &group_body.group_data[cur_block.block_pos], data, size);
                block_t pre_block = cur_block;
                pre_block.protocol_id = s_protocol_seq;
                pre_block.block_bytes = size;
                pre_block.block_pos -= size;
                insert_group_block(group, pre_block, pre_block_index, &pre_buffer[0], size);
            }
        }
        else
        {
            if (group_body.seq_block_bitmap[pre_block_index >> 3] & (1 << (pre_block_index & 7)))
            {
                std::vector<uint8_t> cur_buffer(size, 0x0);
                fill_xor_data(&cur_buffer[0], &group_body.group_data[cur_block.block_pos - size], data, size);
                cur_block.protocol_id = s_protocol_seq;
                insert_group_block(group, cur_block, cur_block_index, &cur_buffer[0], size);
            }
            else
            {
                group_body.xor_block_bitmap[cur_block_index >> 3] |= (1 << (cur_block_index & 7));
                if (cur_block_index + 1 == cur_block.block_count)
                {
                    group_body.group_data.resize(std::max<std::size_t>(group_body.group_data.size(), cur_block.block_pos + size), 0x0);
                }
                memcpy(&group_body.group_data[cur_block.block_pos], data, size);
            }
        }
    }

    return (true);
}

static bool insert_group_block(const void * data, uint32_t size, groups_t & groups, uint32_t max_delay_microseconds)
{
    if (size < sizeof(block_t))
    {
        return (false);
    }

    block_t block = *reinterpret_cast<const block_t *>(data);
    block.decode();

    if (s_protocol_seq != block.protocol_id)
    {
        if (s_protocol_xor != block.protocol_id)
        {
            return (false);
        }
        else if (0 == block.block_idx_h && 0 == block.block_idx_l)
        {
            return (false);
        }
    }

    uint32_t new_block_index = static_cast<uint32_t>(static_cast<uint32_t>(block.block_idx_h) << 16) | static_cast<uint32_t>(block.block_idx_l);
    if (new_block_index >= block.block_count)
    {
        return (false);
    }
    else if (new_block_index + 1 == block.block_count)
    {
        if (sizeof(block) + block.block_bytes > size || block.block_pos + block.block_bytes < block.group_bytes)
        {
            return (false);
        }
    }
    else
    {
        if (sizeof(block) + block.block_bytes != size || block.block_pos + block.block_bytes > block.group_bytes)
        {
            return (false);
        }
    }

    if (block.group_index < groups.min_group_index)
    {
        return (false);
    }

    groups.new_group_index = block.group_index;

    group_t & group = groups.group_items[groups.new_group_index];
    group_head_t & group_head = group.head;
    group_body_t & group_body = group.body;

    if (0 == group_head.need_block_count)
    {
        group_head.group_index = block.group_index;
        group_head.group_bytes = block.group_bytes;
        group_head.need_block_count = block.block_count;

        group_body.seq_block_bitmap.resize((block.block_count + 7) / 8, 0x0);
        group_body.xor_block_bitmap.resize((block.block_count + 7) / 8, 0x0);

        if (s_protocol_seq == block.protocol_id)
        {
            group_head.recv_block_count += 1;
            group_body.xor_block_bitmap[new_block_index >> 3] &= ~static_cast<uint8_t>(1 << (new_block_index & 7));
            group_body.seq_block_bitmap[new_block_index >> 3] |= (1 << (new_block_index & 7));
        }
        else
        {
            group_body.xor_block_bitmap[new_block_index >> 3] |= (1 << (new_block_index & 7));
        }

        group_body.group_data.resize(std::max<std::size_t>(block.group_bytes, block.block_pos + size - sizeof(block)), 0x0);
        memcpy(&group_body.group_data[block.block_pos], reinterpret_cast<const uint8_t *>(data) + sizeof(block), size - sizeof(block));

        decode_timer_t decode_timer = { 0x0 };
        decode_timer.group_index = block.group_index;
        get_current_time(decode_timer.decode_seconds, decode_timer.decode_microseconds);
        decode_timer.decode_microseconds += max_delay_microseconds * (group_head.need_block_count / 100 + 1);
        decode_timer.decode_seconds += decode_timer.decode_microseconds / 1000000;
        decode_timer.decode_microseconds %= 1000000;

        groups.decode_timer_list.push_back(decode_timer);
    }
    else if (group_head.recv_block_count < group_head.need_block_count)
    {
        if (block.group_index != group_head.group_index || block.group_bytes != group_head.group_bytes || block.block_count != group_head.need_block_count)
        {
            return (false);
        }

        return (insert_group_block(group, block, new_block_index, reinterpret_cast<const uint8_t *>(data) + sizeof(block), static_cast<uint32_t>(size - sizeof(block))));
    }

    return (true);
}

static void remove_expired_blocks(groups_t & groups)
{
    std::map<uint64_t, group_t> & group_items = groups.group_items;
    for (std::map<uint64_t, group_t>::iterator iter = group_items.begin(); group_items.end() != iter; iter = group_items.erase(iter))
    {
        if (iter->first >= groups.min_group_index)
        {
            break;
        }
    }
}

static bool check_package(const uint8_t * data, uint32_t size)
{
    if (nullptr == data || size < sizeof(block_t))
    {
        return (false);
    }

    block_t block = *reinterpret_cast<const block_t *>(data);
    block.decode();

    if (s_protocol_seq != block.protocol_id)
    {
        if (s_protocol_xor != block.protocol_id)
        {
            return (false);
        }
        else if (0 == block.block_idx_h && 0 == block.block_idx_l)
        {
            return (false);
        }
    }

    uint32_t block_index = static_cast<uint32_t>(static_cast<uint32_t>(block.block_idx_h) << 16) | static_cast<uint32_t>(block.block_idx_l);
    if (block_index >= block.block_count)
    {
        return (false);
    }
    else if (block_index + 1 == block.block_count)
    {
        if (sizeof(block) + block.block_bytes > size || block.block_pos + block.block_bytes < block.group_bytes)
        {
            return (false);
        }
    }
    else
    {
        if (sizeof(block) + block.block_bytes != size || block.block_pos + block.block_bytes > block.group_bytes)
        {
            return (false);
        }
    }

    return (true);
}

static bool packet_unify(const void * data, uint32_t size, groups_t & groups, std::list<std::vector<uint8_t>> & dst_list, uint32_t max_delay_microseconds, double fault_tolerance_rate, decode_callback_t * decode_callback, void * user_data)
{
    if (nullptr != data && 0 != size)
    {
        if (!insert_group_block(data, size, groups, max_delay_microseconds))
        {
        //  return (false);
        }

        group_t & group = groups.group_items[groups.new_group_index];
        if (group.head.recv_block_count != group.head.need_block_count && groups.new_group_index < groups.min_group_index + 3)
        {
        //  return (false);
        }
    }

    const std::size_t old_dst_list_size = dst_list.size();

    uint32_t current_seconds = 0;
    uint32_t current_microseconds = 0;
    get_current_time(current_seconds, current_microseconds);
    std::list<decode_timer_t>::iterator iter = groups.decode_timer_list.begin();
    while (groups.decode_timer_list.end() != iter)
    {
        const decode_timer_t & decode_timer = *iter;
        group_t & group = groups.group_items[decode_timer.group_index];
        if (group.head.recv_block_count == group.head.need_block_count)
        {
            group.body.group_data.resize(group.head.group_bytes, 0x0);
            if (nullptr != decode_callback)
            {
                (*decode_callback)(user_data, &group.body.group_data[0], static_cast<uint32_t>(group.body.group_data.size()));
            }
            dst_list.emplace_back(std::move(group.body.group_data));
            groups.group_items.erase(decode_timer.group_index);
            groups.min_group_index = decode_timer.group_index + 1;
            iter = groups.decode_timer_list.erase(iter);
        }
        else if ((decode_timer.decode_seconds < current_seconds) || (decode_timer.decode_seconds == current_seconds && decode_timer.decode_microseconds < current_microseconds))
        {
            if (fault_tolerance_rate > 0.0 && fault_tolerance_rate < 1.0)
            {
                if (group.head.recv_block_count >= static_cast<uint32_t>(group.head.need_block_count * (1.0 - fault_tolerance_rate)))
                {
                    group.body.group_data.resize(group.head.group_bytes, 0x0);
                    if (nullptr != decode_callback)
                    {
                        (*decode_callback)(user_data, &group.body.group_data[0], static_cast<uint32_t>(group.body.group_data.size()));
                    }
                    dst_list.emplace_back(std::move(group.body.group_data));
                }
            }
            groups.group_items.erase(decode_timer.group_index);
            groups.min_group_index = decode_timer.group_index + 1;
            iter = groups.decode_timer_list.erase(iter);
        }
        else
        {
            break;
        }
    }

    const std::size_t new_dst_list_size = dst_list.size();

    remove_expired_blocks(groups);

    return (new_dst_list_size > old_dst_list_size);
}

class PacketXorDividerImpl
{
public:
    PacketXorDividerImpl(uint32_t max_block_size, bool use_xor);
    PacketXorDividerImpl(const PacketXorDividerImpl &) = delete;
    PacketXorDividerImpl(PacketXorDividerImpl &&) = delete;
    PacketXorDividerImpl & operator = (const PacketXorDividerImpl &) = delete;
    PacketXorDividerImpl & operator = (PacketXorDividerImpl &&) = delete;
    ~PacketXorDividerImpl();

public:
    bool encode(const uint8_t * src_data, uint32_t src_size, std::list<std::vector<uint8_t>> & dst_list);
    bool encode(const uint8_t * src_data, uint32_t src_size, encode_callback_t * encode_callback, void * user_data);

public:
    void reset();

private:
    const uint32_t      m_max_block_size;
    const bool          m_use_xor;

private:
    uint64_t            m_group_index;
};

PacketXorDividerImpl::PacketXorDividerImpl(uint32_t max_block_size, bool use_xor)
    : m_max_block_size(std::max<uint32_t>(max_block_size, sizeof(block_t) + 1))
    , m_use_xor(use_xor)
    , m_group_index(0)
{

}

PacketXorDividerImpl::~PacketXorDividerImpl()
{

}

bool PacketXorDividerImpl::encode(const uint8_t * src_data, uint32_t src_size, std::list<std::vector<uint8_t>> & dst_list)
{
    return (packet_divide(src_data, src_size, m_max_block_size, m_use_xor, m_group_index, dst_list, nullptr, nullptr));
}

bool PacketXorDividerImpl::encode(const uint8_t * src_data, uint32_t src_size, encode_callback_t * encode_callback, void * user_data)
{
    std::list<std::vector<uint8_t>> dst_list;
    return (packet_divide(src_data, src_size, m_max_block_size, m_use_xor, m_group_index, dst_list, encode_callback, user_data));
}

void PacketXorDividerImpl::reset()
{
    m_group_index = 0;
}

class PacketXorUnifierImpl
{
public:
    PacketXorUnifierImpl(uint32_t max_delay_microseconds = 1000 * 15, double fault_tolerance_rate = 0.0);
    PacketXorUnifierImpl(const PacketXorUnifierImpl &) = delete;
    PacketXorUnifierImpl(PacketXorUnifierImpl &&) = delete;
    PacketXorUnifierImpl & operator = (const PacketXorUnifierImpl &) = delete;
    PacketXorUnifierImpl & operator = (PacketXorUnifierImpl &&) = delete;
    ~PacketXorUnifierImpl();

public:
    bool decode(const uint8_t * src_data, uint32_t src_size, std::list<std::vector<uint8_t>> & dst_list);
    bool decode(const uint8_t * src_data, uint32_t src_size, decode_callback_t * decode_callback, void * user_data);

public:
    static bool recognizable(const uint8_t * src_data, uint32_t src_size);

public:
    void reset();

private:
    const uint32_t      m_max_delay_microseconds;
    const double        m_fault_tolerance_rate;

private:
    groups_t            m_groups;
};

PacketXorUnifierImpl::PacketXorUnifierImpl(uint32_t max_delay_microseconds, double fault_tolerance_rate)
    : m_max_delay_microseconds(std::max<uint32_t>(max_delay_microseconds, 500))
    , m_fault_tolerance_rate(std::max<double>(std::min<double>(fault_tolerance_rate, 1.0), 0.0))
    , m_groups()
{

}

PacketXorUnifierImpl::~PacketXorUnifierImpl()
{

}

bool PacketXorUnifierImpl::decode(const uint8_t * src_data, uint32_t src_size, std::list<std::vector<uint8_t>> & dst_list)
{
    return (packet_unify(src_data, src_size, m_groups, dst_list, m_max_delay_microseconds, m_fault_tolerance_rate, nullptr, nullptr));
}

bool PacketXorUnifierImpl::decode(const uint8_t * src_data, uint32_t src_size, decode_callback_t * decode_callback, void * user_data)
{
    std::list<std::vector<uint8_t>> dst_list;
    return (packet_unify(src_data, src_size, m_groups, dst_list, m_max_delay_microseconds, m_fault_tolerance_rate, decode_callback, user_data));
}

bool PacketXorUnifierImpl::recognizable(const uint8_t * src_data, uint32_t src_size)
{
    return (check_package(src_data, src_size));
}

void PacketXorUnifierImpl::reset()
{
    m_groups.reset();
}

PacketXorDivider::PacketXorDivider()
    : m_divider(nullptr)
{

}

PacketXorDivider::~PacketXorDivider()
{
    exit();
}

bool PacketXorDivider::init(uint32_t max_block_size, bool use_xor)
{
    exit();

    return (nullptr != (m_divider = new PacketXorDividerImpl(max_block_size, use_xor)));
}

void PacketXorDivider::exit()
{
    if (nullptr != m_divider)
    {
        delete m_divider;
        m_divider = nullptr;
    }
}

bool PacketXorDivider::encode(const uint8_t * src_data, uint32_t src_size, std::list<std::vector<uint8_t>> & dst_list)
{
    return (nullptr != m_divider && m_divider->encode(src_data, src_size, dst_list));
}

bool PacketXorDivider::encode(const uint8_t * src_data, uint32_t src_size, encode_callback_t * encode_callback, void * user_data)
{
    return (nullptr != m_divider && m_divider->encode(src_data, src_size, encode_callback, user_data));
}

void PacketXorDivider::reset()
{
    if (nullptr != m_divider)
    {
        m_divider->reset();
    }
}

PacketXorUnifier::PacketXorUnifier()
    : m_unifier(nullptr)
{

}

PacketXorUnifier::~PacketXorUnifier()
{
    exit();
}

bool PacketXorUnifier::init(uint32_t expire_millisecond, double fault_tolerance_rate)
{
    exit();

    return (nullptr != (m_unifier = new PacketXorUnifierImpl(expire_millisecond * 1000, fault_tolerance_rate)));
}

void PacketXorUnifier::exit()
{
    if (nullptr != m_unifier)
    {
        delete m_unifier;
        m_unifier = nullptr;
    }
}

bool PacketXorUnifier::decode(const uint8_t * src_data, uint32_t src_size, std::list<std::vector<uint8_t>> & dst_list)
{
    return (nullptr != m_unifier && m_unifier->decode(src_data, src_size, dst_list));
}

bool PacketXorUnifier::decode(const uint8_t * src_data, uint32_t src_size, decode_callback_t * decode_callback, void * user_data)
{
    return (nullptr != m_unifier && m_unifier->decode(src_data, src_size, decode_callback, user_data));
}

bool PacketXorUnifier::recognizable(const uint8_t * src_data, uint32_t src_size)
{
    return (PacketXorUnifierImpl::recognizable(src_data, src_size));
}

void PacketXorUnifier::reset()
{
    if (nullptr != m_unifier)
    {
        m_unifier->reset();
    }
}
