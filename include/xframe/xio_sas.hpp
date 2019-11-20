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
        constexpr uint64_t sas_subheader_pointer_size_64bit = 40;

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

        struct sas_header_end {
            char release[8];
            char host[16];
            char version[16];
            char os_vendor[16];
            char os_name[16];
            char extra[48];
        };

#pragma pack(pop)

        class xsas_reader
        {
        public:
            explicit xsas_reader(std::string&);

            xsas_reader(xsas_reader&) = delete;
            xsas_reader(xsas_reader&&) = delete;
            xsas_reader& operator=(const xsas_reader&) = delete;
            xsas_reader& operator=(xsas_reader&&) = delete;

            axis read_header();
        private:
            inline auto little_endian() {
                const int test_byte_order = 1;
                return ((char *)&test_byte_order)[0] != 0;
            }

            std::unique_ptr<std::ifstream> m_sas_ifs;
            uint64_t m_a1;
            uint64_t m_a2;
        };

        xsas_reader::xsas_reader(std::string& file_path)
        {
            m_sas_ifs = std::make_unique<std::ifstream>(file_path, std::ios::in | std::ifstream::binary);
            if (!m_sas_ifs.is_open())
                throw std::runtime_error(file_path << " does not exsit");
        }

        axis xsas_reader::read_header()
        {
            sas_header_begin header_begin;
            if (!m_sas_ifs->read(header_begin, sizeof(header_begin)))
                throw std::runtime_error("read header failed");
            
            if (std::memcmp(header_begin.magic_number, sas7bdat_magic_number, sizeof(sas7bdat_magic_number)) != 0)
                throw std::runtime_error("error");
            
            auto a1 = 0;
            if (header_begin.a1 == sas_aligment_offset_4)
                a1 = 4;
            auto u64 = 0;
            if (header_begin.a2 = sas_aligment_offset_4)
                u64 = 1;
            auto swap = false;    
            if (header_begin.endian == sas_endian_big) 
            {
                swap = little_endian();
            } 
            else if (header_start.endian == sas_endian_little)
                swap = !little_endian();
            else 
                throw std::runtime_error("parse sas error");

            auto file_label = std::string(header_begin.file_label, sizeof(header_begin.file_label));
            if (!m_sas_ifs.seekg(a1, m_sas_ifs.cur))
                throw std::runtime_error("parse sas error");
            
            auto creation_time = 0.0f;
            auto modification_time = 0.0f;
            if (!m_sas_ifs->read(&creation_time, sizeof(creation_time)))
                throw std::runtime_error("");
            
            if (!m_sas_ifs->read(&modification_time, sizeof(modification_time)))
                throw std::runtime_error("");

            if (!m_sas_ifs.seekg(16, m_sas_ifs.cur))
                throw std::runtime_error("");
        }
    }
}

#endif
