/***************************************************************************
* Copyright (c) Johan Mabille, Sylvain Corlay, Wolf Vollprecht and         *
* Martin Renou                                                             *
* Copyright (c) QuantStack                                                 *
*                                                                          *
* Distributed under the terms of the BSD 3-Clause License.                 *
*                                                                          *
* The full license is in the file LICENSE, distributed with this software. *
****************************************************************************/

#ifndef XFRAME_IO_SAS_HPP
#define XFRAME_IO_SAS_HPP

#include <string>
#include <memory>

#include <cstring>

#include "xaxis.hpp"

namespace xf
{
    void read_sas();
    namespace detail 
    {
        constexpr uint8_t sas_endian_big = 0x00;
        constexpr uint8_t sas_endian_little = 0x01;

        constexpr char sas_file_format_unix = '1';
        constexpr char sas_file_format_windows = '2';

        constexpr uint8_t sas_aligment_offset_0 = 0x22;
        constexpr uint8_t sas_aligment_offset_4 = 0x33;

        constexpr uint8_t sas_column_type_number = 0x01;
        constexpr uint8_t sas_column_type_char = 0x02;

        constexpr uint32_t sas_subheader_signature_row_size = 0xF7F7F7F7;
        constexpr uint32_t sas_subheader_signature_column_size = 0xF6F6F6F6;
        constexpr uint32_t sas_subheader_signature_counts = 0xFFFFFC00;
        constexpr uint32_t sas_subheader_signature_column_format = 0xFFFFFBFE;

        constexpr uint32_t sas_subheader_signature_column_attrs = 0xFFFFFFFC;
        constexpr uint32_t sas_subheader_signature_column_text = 0xFFFFFFFD;
        constexpr uint32_t sas_subheader_signature_column_list = 0xFFFFFFFE;
        constexpr uint32_t sas_subheader_signature_column_name = 0xFFFFFFFF;

        constexpr uint16_t sas_page_type_meta = 0x0000;
        constexpr uint16_t sas_page_type_data = 0x0100;
        constexpr uint16_t sas_page_type_mix = 0x0200;
        constexpr uint16_t sas_page_type_amd = 0x0400;
        constexpr uint16_t sas_page_type_mask = 0x0F00;

        constexpr uint16_t sas_page_type_meta2 = 0x4000;
        constexpr uint16_t sas_page_type_comp = 0x9000;

        constexpr uint64_t sas_subheader_pointer_size_32bit = 12;
        constexpr uint64_t sas_subheader_pointer_size_64bit = 24;

        constexpr uint64_t sas_page_header_size_32bit = 24;
        constexpr uint64_t sas_page_header_size_64bit = 40;

        constexpr uint8_t sas_compression_none = 0x00;
        constexpr uint8_t sas_compression_trunc = 0x01;
        constexpr uint8_t sas_compression_row = 0x04;

        constexpr uint64_t sas_default_file_version = 9;

        constexpr unsigned char sas7bdat_magic_number[32] = {
            0x00, 0x00, 0x00, 0x00,   0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,   0xc2, 0xea, 0x81, 0x60,
            0xb3, 0x14, 0x11, 0xcf,   0xbd, 0x92, 0x08, 0x00,
            0x09, 0xc7, 0x31, 0x8c,   0x18, 0x1f, 0x10, 0x11
        };

        constexpr unsigned char sas7bcat_magic_number[32] = {
            0x00, 0x00, 0x00, 0x00,   0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,   0xc2, 0xea, 0x81, 0x63,
            0xb3, 0x14, 0x11, 0xcf,   0xbd, 0x92, 0x08, 0x00,
            0x09, 0xc7, 0x31, 0x8c,   0x18, 0x1f, 0x10, 0x11
        };

        class xsas7bdat_reader
        {
        public:
            explicit xsas7bdat_reader(std::string&);

            xsas7bdat_reader(xsas7bdat_reader&) = delete;
            xsas7bdat_reader(xsas7bdat_reader&&) = delete;
            xsas7bdat_reader& operator=(const xsas7bdat_reader&) = delete;
            xsas7bdat_reader& operator=(xsas7bdat_reader&&) = delete;

            
        private:
            inline bool little_endian()
            {
                const int value { 0x01 };
                const void * address = static_cast<const void *>(&value);
                const unsigned char * least_significant_address = static_cast<const unsigned char *>(address);
                return (*least_significant_address == 0x01);
            }
            template <typename T>
            inline auto swap_endian(const T&) -> T;
            template <typename T>
            inline auto read_data(const std::ifstream& ,bool) -> T;

            inline void parse_head();

            int64_t m_page_count {0};
            int32_t m_header_size {0};
            int32_t m_page_size {0};
            bool m_u64 {false};
            bool m_swap {false};
            std::unique_ptr<std::ifstream> m_sas_ifs;
        };

        xsas7bdat_reader::xsas7bdat_reader(std::string& file_path)
        {
            m_sas_ifs = std::make_unique<std::ifstream>(file_path, std::ios::in | std::ifstream::binary);
            if (!m_sas_ifs.is_open())
                throw std::runtime_error(file_path << " does not exsit");
        }

        template <typename T>
        inline auto swap_endian(const T &val) -> T
        {
            union 
            {
                T val;
                std::array<std::uint8_t, sizeof(T)> raw;
            } src, dst;
            src.val = val;
            std::reverse_copy(src.raw.begin(), src.raw.end(), dst.raw.begin());
            return dst.val;
        }

        template <typename T>
        inline auto read_sas_data(const std::ifstream& ifs ,bool swap) -> T
        {
            T data;
            if (!ifs.read(&data, sizeof(data)))
                throw std::runtime_error("");
            if (swap)
                data = swap_endian(data);
            return data;
        }

        template <typename T>
        inline auto read_sas_data(std::string::iterator& memory_it, bool swap) -> T
        {
            T data;
            std::string str(memory_it, memory_it + sizeof(T));
            str.copy(&data, sizeof(T), 0);
            if (swap)
                data = swap_endian(data);
            memory_it += sizeof(T);
            return data;
        }

        inline void seekg(std::string::iterator& memory_it, size_t pos)
        {
            memory_it += pos;
            return;
        }

        void xsas7bdat_reader::parse_head()
        {
        #pragma pack(push, 1)
                struct sas_header_begin
                {
                    unsigned char magic_number[32];
                    unsigned char a2;
                    unsigned char mystery1[2];
                    unsigned char a1;
                    unsigned char mystery2[1];
                    unsigned char endian;
                    unsigned char mystery3[1];
                    char file_format;
                    unsigned char mystery4[30];
                    unsigned char encoding;
                    unsigned char mystery5[13];
                    char file_type[8];
                    char file_label[64];
                    char file_info[8];
                };
        #pragma pack(pop)
            sas_header_begin header_begin;
            if (!m_sas_ifs->read(header_begin, sizeof(header_begin)))
                throw std::runtime_error("read header failed");
            if (std::memcmp(header_begin.magic_number, sas7bdat_magic_number, sizeof(sas7bdat_magic_number)) != 0)
                throw std::runtime_error("error");
            auto a1 = 0;
            if (header_begin.a1 == sas_aligment_offset_4)
                a1 = 4;
            if (header_begin.a2 = sas_aligment_offset_4)
                m_u64 = true;
            m_swap = false;    
            if (header_begin.endian == sas_endian_big) 
                m_swap = little_endian();
            else if (header_begin.endian == sas_endian_little)
                m_swap = !little_endian();
            else 
                throw std::runtime_error("parse sas error");

            if (!m_sas_ifs.seekg(a1 + sizeof(double) * 2 + 16, m_sas_ifs.cur))
                throw std::runtime_error("parse sas error");

            m_header_size = read_sas_data<uint32_t>(*m_sas_ifs, m_swap);
            m_page_size = read_sas_data<uint32_t>(*m_sas_ifs, m_swap);
            if (m_header_size < 1024 || m_page_size < 1024)
                throw std::runtime_error("");
            if (m_header_size > (1 << 20) || m_page_size > (1 << 24))
                throw std::runtime_error("");

            if (m_u64)
                m_page_count = read_sas_data<uint64_t>(*m_sas_ifs, m_swap);
            else
                m_page_count = read_sas_data<uint32_t>(*m_sas_ifs, m_swap);
            if (m_page_count > (1 << 24))
                throw std::runtime_error("");
        }
        
        void xsas7bdat_reader::parse_page()
        {
            auto page_header_size = m_u64 ? sas_page_header_size_64bit : sas_page_header_size_32bit;
            auto subheader_pointer_size = m_u64 ? sas_subheader_pointer_size_64bit : sas_subheader_pointer_size_32bit;
            auto subheader_signature_size = m_u64 ? 8 : 4;
            for (auto idx : m_page_count)
            {
                
                auto page_offset = m_header_size + idx * m_page_size;
                if (!m_sas_ifs.seekg(page_offset, m_sas_ifs.begin))
                    throw std::runtime_error("parse sas error");
                
                std::string page_memory;
                m_sas_ifs->read(&page_memory[0], m_page_size);
                auto it = page_memory.begin();

                auto signature = read_sas_data<uint32_t>(it, m_swap);
                if (m_u64)
                    seekg(it, 12);
                else
                    seekg(it, 28);
                auto page_type = read_sas_data<uint16_t>(it, m_swap);
                if ((page_type & SAS_PAGE_TYPE_MASK) == SAS_PAGE_TYPE_DATA)
                    break;
                if ((page_type & SAS_PAGE_TYPE_COMP))
                    continue;
                auto data_block_count = read_sas_data<uint16_t>(it, m_swap);
                auto subheader_pointers_count = read_sas_data<uint16_t>(it, m_swap);
                seekg(it, 2);

                for (auto idx : subheader_pointers_count)
                {  
                    it = page_memory.begin() + subheader_pointer_size * idx;
                    [auto offset_to_subhead, auto length, auto compression, auto subheader_type] = parse_subheader_pointer(it);
                    if (compression != sas_compression_trunc)
                    {
                        if (offset_to_subhead > m_page_size)
                            throw std::runtime_error("parse sas error");
                        else if (length > m_page_size)
                            throw std::runtime_error("");
                        else if (offset_to_subhead + length > m_page_size)
                            throw std::runtime_error("");
                        else if (offset_to_subhead < m_header_size + page_header_size + subheader_pointer_size * subheader_pointers_count)
                            throw std::runtime_error("");
                        else if (compression == sas_compression_none)
                        {
                            if (length < subheader_signature_size)
                                throw std::runtime_error("");
                            else if (offset + subheader_signature_size > m_page_size)
                                throw std::runtime_error("");
                            else
                            {
                                it = page_memory.begin() + offset_to_subhead;
                                parse_subheader();
                            }
                        }
                        else if (shp_info.compression == sas_compression_row) 
                        {
                            // do nothing
                        }
                        else
                        {
                            throw std::runtime_error("");
                        }
                    }

                }
            }
        }

        std::tuple<uint64_t, uint64_t, uint8_t, uint8_t> xsas7bdat_reader::parse_subheader_pointer(std::string::iterator& it)
        {
            auto offset_to_subhead = 0;
            auto length = 0;
            auto compression = 0;
            auto subheader_type = 0;
            if (m_u64) 
            {
                offset_to_subhead = read_sas_data<uint64_t>(it, m_swap);
                length = read_sas_data<uint64_t>(it, m_swap);
                compression = read_sas_data<uint8_t>(it, m_swap);
                subheader_type = read_sas_data<uint8_t>(it, m_swap);
                seekg(it, 7);
            }
            else 
            {
                offset_to_subhead = read_sas_data<uint32_t>(it, m_swap);
                length = read_sas_data<uint32_t>(it, m_swap);
                compression = read_sas_data<uint8_t>(it, m_swap);
                subheader_type = read_sas_data<uint8_t>(it, m_swap);
                seekg(it, 3);
            }
            return std::make_tuple(offset_to_subhead, length, compression, subheader_type);
        }

        void xsas7bdat_reader::parse_subheader(std::string::iterator& it, )
        {
            auto subheader_signature_size = m_u64 ? 8 : 4;
            auto signature = read_sas_data<int32_t>(it, m_swap);
            if (subheader_signature_size == 8)
                signature = read_sas_data<int32_t>(it, m_swap);
            if (signature != sas_subheader_signature_column_text)
                return;
        }

        void xsas7bdat_reader::parse_row_size_subheader(uint64_t length)
        {
            if (length < (m_u64 ? 128 : 64))
                throw std::runtime_error("");

            if (m_u64)
            {
                auto mystery_size = 32;
                if (!m_sas_ifs->seekg(mystery_size, m_sas_ifs.cur))
                    throw std::runtime_error("");
                uint64_t row_length = read_data(*m_sas_ifs, m_swap);
                uint64_t total_row_count = read_data(*m_sas_ifs, m_swap);
                if (!m_sas_ifs->seekg(mystery_size, m_sas_ifs.cur))
                    throw std::runtime_error("");
                uint64_t page_row_count = read_data(*m_sas_ifs, m_swap);
            }
        }
    }
}

#endif
