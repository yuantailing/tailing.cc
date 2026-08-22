// MIT License
// 
// Copyright (c) 2018 Tiger
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


// Copyright (c) 2014, ipkn
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
// 
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
// 
// * Neither the name of the author nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <boost/optional.hpp>
#include <sys/types.h>
#include <stdint.h>
#include <assert.h>
#include <stddef.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/functional/hash.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <boost/asio.hpp>
#include <algorithm>
#include <memory>
#include <boost/lexical_cast.hpp>
#include <boost/operators.hpp>
#include <fstream>
#include <iterator>
#include <functional>
#include <ctime>
#include <sstream>
#include <deque>
#include <chrono>
#include <thread>
#include <cstdint>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <boost/array.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <utility>
#include <atomic>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <future>
#include <condition_variable>






       

       









namespace crow
{





int qs_strncmp(const char * s, const char * qs, size_t n);






int qs_parse(char * qs, char * qs_kv[], int qs_kv_size);



int qs_decode(char * qs);






 char * qs_k2v(const char * key, char * const * qs_kv, int qs_kv_size, int nth);




char * qs_scanvalue(const char * key, const char * qs, char * val, size_t val_len);

inline int qs_strncmp(const char * s, const char * qs, size_t n)
{
    int i=0;
    unsigned char u1, u2, unyb, lnyb;

    while(n-- > 0)
    {
        u1 = (unsigned char) *s++;
        u2 = (unsigned char) *qs++;

        if ( ! ((((u1)=='=')||((u1)=='#')||((u1)=='&')||((u1)=='\0')) ? 0 : 1) ) { u1 = '\0'; }
        if ( ! ((((u2)=='=')||((u2)=='#')||((u2)=='&')||((u2)=='\0')) ? 0 : 1) ) { u2 = '\0'; }

        if ( u1 == '+' ) { u1 = ' '; }
        if ( u1 == '%' )
        {
            unyb = (unsigned char) *s++;
            lnyb = (unsigned char) *s++;
            if ( ((((unyb)>='0'&&(unyb)<='9') || ((unyb)>='A'&&(unyb)<='F') || ((unyb)>='a'&&(unyb)<='f')) ? 1 : 0) && ((((lnyb)>='0'&&(lnyb)<='9') || ((lnyb)>='A'&&(lnyb)<='F') || ((lnyb)>='a'&&(lnyb)<='f')) ? 1 : 0) )
                u1 = ((((unyb)>='0'&&(unyb)<='9') ? (unyb)-48 : ((unyb)>='A'&&(unyb)<='F') ? (unyb)-55 : ((unyb)>='a'&&(unyb)<='f') ? (unyb)-87 : 0) * 16) + (((lnyb)>='0'&&(lnyb)<='9') ? (lnyb)-48 : ((lnyb)>='A'&&(lnyb)<='F') ? (lnyb)-55 : ((lnyb)>='a'&&(lnyb)<='f') ? (lnyb)-87 : 0);
            else
                u1 = '\0';
        }

        if ( u2 == '+' ) { u2 = ' '; }
        if ( u2 == '%' )
        {
            unyb = (unsigned char) *qs++;
            lnyb = (unsigned char) *qs++;
            if ( ((((unyb)>='0'&&(unyb)<='9') || ((unyb)>='A'&&(unyb)<='F') || ((unyb)>='a'&&(unyb)<='f')) ? 1 : 0) && ((((lnyb)>='0'&&(lnyb)<='9') || ((lnyb)>='A'&&(lnyb)<='F') || ((lnyb)>='a'&&(lnyb)<='f')) ? 1 : 0) )
                u2 = ((((unyb)>='0'&&(unyb)<='9') ? (unyb)-48 : ((unyb)>='A'&&(unyb)<='F') ? (unyb)-55 : ((unyb)>='a'&&(unyb)<='f') ? (unyb)-87 : 0) * 16) + (((lnyb)>='0'&&(lnyb)<='9') ? (lnyb)-48 : ((lnyb)>='A'&&(lnyb)<='F') ? (lnyb)-55 : ((lnyb)>='a'&&(lnyb)<='f') ? (lnyb)-87 : 0);
            else
                u2 = '\0';
        }

        if ( u1 != u2 )
            return u1 - u2;
        if ( u1 == '\0' )
            return 0;
        i++;
    }
    if ( ((((*qs)=='=')||((*qs)=='#')||((*qs)=='&')||((*qs)=='\0')) ? 0 : 1) )
        return -1;
    else
        return 0;
}


inline int qs_parse(char * qs, char * qs_kv[], int qs_kv_size)
{
    int i, j;
    char * substr_ptr;

    for(i=0; i<qs_kv_size; i++) qs_kv[i] = NULL;


    substr_ptr = qs + strcspn(qs, "?#");
    if (substr_ptr[0] != '\0')
        substr_ptr++;
    else
        return 0;

    i=0;
    while(i<qs_kv_size)
    {
        qs_kv[i] = substr_ptr;
        j = strcspn(substr_ptr, "&");
        if ( substr_ptr[j] == '\0' ) { break; }
        substr_ptr += j + 1;
        i++;
    }
    i++;



    for(j=0; j<i; j++)
    {
        substr_ptr = qs_kv[j] + strcspn(qs_kv[j], "=&#");
        if ( substr_ptr[0] == '&' || substr_ptr[0] == '\0')
            substr_ptr[0] = '\0';
        else
            qs_decode(++substr_ptr);
    }





    return i;
}


inline int qs_decode(char * qs)
{
    int i=0, j=0;

    while( ((((qs[j])=='=')||((qs[j])=='#')||((qs[j])=='&')||((qs[j])=='\0')) ? 0 : 1) )
    {
        if ( qs[j] == '+' ) { qs[i] = ' '; }
        else if ( qs[j] == '%' )
        {
            if ( ! ((((qs[j+1])>='0'&&(qs[j+1])<='9') || ((qs[j+1])>='A'&&(qs[j+1])<='F') || ((qs[j+1])>='a'&&(qs[j+1])<='f')) ? 1 : 0) || ! ((((qs[j+2])>='0'&&(qs[j+2])<='9') || ((qs[j+2])>='A'&&(qs[j+2])<='F') || ((qs[j+2])>='a'&&(qs[j+2])<='f')) ? 1 : 0) )
            {
                qs[i] = '\0';
                return i;
            }
            qs[i] = ((((qs[j+1])>='0'&&(qs[j+1])<='9') ? (qs[j+1])-48 : ((qs[j+1])>='A'&&(qs[j+1])<='F') ? (qs[j+1])-55 : ((qs[j+1])>='a'&&(qs[j+1])<='f') ? (qs[j+1])-87 : 0) * 16) + (((qs[j+2])>='0'&&(qs[j+2])<='9') ? (qs[j+2])-48 : ((qs[j+2])>='A'&&(qs[j+2])<='F') ? (qs[j+2])-55 : ((qs[j+2])>='a'&&(qs[j+2])<='f') ? (qs[j+2])-87 : 0);
            j+=2;
        }
        else
        {
            qs[i] = qs[j];
        }
        i++; j++;
    }
    qs[i] = '\0';

    return i;
}


inline char * qs_k2v(const char * key, char * const * qs_kv, int qs_kv_size, int nth = 0)
{
    int i;
    size_t key_len, skip;

    key_len = strlen(key);




    for(i=0; i<qs_kv_size; i++)
    {

        if ( qs_strncmp(key, qs_kv[i], key_len) == 0 )
        {
            skip = strcspn(qs_kv[i], "=");
            if ( qs_kv[i][skip] == '=' )
                skip++;

            if(nth == 0)
                return qs_kv[i] + skip;
            else
                --nth;
        }
    }


    return NULL;
}

inline boost::optional<std::pair<std::string, std::string>> qs_dict_name2kv(const char * dict_name, char * const * qs_kv, int qs_kv_size, int nth = 0)
{
    int i;
    size_t name_len, skip_to_eq, skip_to_brace_open, skip_to_brace_close;

    name_len = strlen(dict_name);




    for(i=0; i<qs_kv_size; i++)
    {
        if ( strncmp(dict_name, qs_kv[i], name_len) == 0 )
        {
            skip_to_eq = strcspn(qs_kv[i], "=");
            if ( qs_kv[i][skip_to_eq] == '=' )
                skip_to_eq++;
            skip_to_brace_open = strcspn(qs_kv[i], "[");
            if ( qs_kv[i][skip_to_brace_open] == '[' )
                skip_to_brace_open++;
            skip_to_brace_close = strcspn(qs_kv[i], "]");

            if ( skip_to_brace_open <= skip_to_brace_close &&
                 skip_to_brace_open > 0 &&
                 skip_to_brace_close > 0 &&
                 nth == 0 )
            {
                auto key = std::string(qs_kv[i] + skip_to_brace_open, skip_to_brace_close - skip_to_brace_open);
                auto value = std::string(qs_kv[i] + skip_to_eq);
                return boost::make_optional(std::make_pair(key, value));
            }
            else
            {
                --nth;
            }
        }
    }


    return boost::none;
}


inline char * qs_scanvalue(const char * key, const char * qs, char * val, size_t val_len)
{
    size_t i, key_len;
    const char * tmp;


    if ( (tmp = strchr(qs, '?')) != NULL )
        qs = tmp + 1;

    key_len = strlen(key);
    while(qs[0] != '#' && qs[0] != '\0')
    {
        if ( qs_strncmp(key, qs, key_len) == 0 )
            break;
        qs += strcspn(qs, "&") + 1;
    }

    if ( qs[0] == '\0' ) return NULL;

    qs += strcspn(qs, "=&#");
    if ( qs[0] == '=' )
    {
        qs++;
        i = strcspn(qs, "&=#");



        strncpy(val, qs, (val_len - 1)<(i + 1) ? (val_len - 1) : (i + 1));

  qs_decode(val);
    }
    else
    {
        if ( val_len > 0 )
            val[0] = '\0';
    }

    return val;
}
}



namespace crow
{
    class query_string
    {
    public:
        static const int MAX_KEY_VALUE_PAIRS_COUNT = 256;

        query_string()
        {

        }

        query_string(const query_string& qs)
            : url_(qs.url_)
        {
            for(auto p:qs.key_value_pairs_)
            {
                key_value_pairs_.push_back((char*)(p-qs.url_.c_str()+url_.c_str()));
            }
        }

        query_string& operator = (const query_string& qs)
        {
            url_ = qs.url_;
            key_value_pairs_.clear();
            for(auto p:qs.key_value_pairs_)
            {
                key_value_pairs_.push_back((char*)(p-qs.url_.c_str()+url_.c_str()));
            }
            return *this;
        }

        query_string& operator = (query_string&& qs)
        {
            key_value_pairs_ = std::move(qs.key_value_pairs_);
            char* old_data = (char*)qs.url_.c_str();
            url_ = std::move(qs.url_);
            for(auto& p:key_value_pairs_)
            {
                p += (char*)url_.c_str() - old_data;
            }
            return *this;
        }


        query_string(std::string url)
            : url_(std::move(url))
        {
            if (url_.empty())
                return;

            key_value_pairs_.resize(MAX_KEY_VALUE_PAIRS_COUNT);

            int count = qs_parse(&url_[0], &key_value_pairs_[0], MAX_KEY_VALUE_PAIRS_COUNT);
            key_value_pairs_.resize(count);
        }

        void clear()
        {
            key_value_pairs_.clear();
            url_.clear();
        }

        friend std::ostream& operator<<(std::ostream& os, const query_string& qs)
        {
            os << "[ ";
            for(size_t i = 0; i < qs.key_value_pairs_.size(); ++i) {
                if (i)
                    os << ", ";
                os << qs.key_value_pairs_[i];
            }
            os << " ]";
            return os;

        }

        char* get (const std::string& name) const
        {
            char* ret = qs_k2v(name.c_str(), key_value_pairs_.data(), key_value_pairs_.size());
            return ret;
        }

        std::vector<char*> get_list (const std::string& name) const
        {
            std::vector<char*> ret;
            std::string plus = name + "[]";
            char* element = nullptr;

            int count = 0;
            while(1)
            {
                element = qs_k2v(plus.c_str(), key_value_pairs_.data(), key_value_pairs_.size(), count++);
                if (!element)
                    break;
                ret.push_back(element);
            }
            return ret;
        }

        std::unordered_map<std::string, std::string> get_dict (const std::string& name) const
        {
            std::unordered_map<std::string, std::string> ret;

            int count = 0;
            while(1)
            {
                if (auto element = qs_dict_name2kv(name.c_str(), key_value_pairs_.data(), key_value_pairs_.size(), count++))
                    ret.insert(*element);
                else
                    break;
            }
            return ret;
        }

    private:
        std::string url_;
        std::vector<char*> key_value_pairs_;
    };

}



extern "C" {











typedef struct http_parser http_parser;
typedef struct http_parser_settings http_parser_settings;

typedef int (*http_data_cb) (http_parser*, const char *at, size_t length);
typedef int (*http_cb) (http_parser*);

enum http_method
  {

  HTTP_DELETE = 0, HTTP_GET = 1, HTTP_HEAD = 2, HTTP_POST = 3, HTTP_PUT = 4, HTTP_CONNECT = 5, HTTP_OPTIONS = 6, HTTP_TRACE = 7, HTTP_PATCH = 8, HTTP_PURGE = 9, HTTP_COPY = 10, HTTP_LOCK = 11, HTTP_MKCOL = 12, HTTP_MOVE = 13, HTTP_PROPFIND = 14, HTTP_PROPPATCH = 15, HTTP_SEARCH = 16, HTTP_UNLOCK = 17, HTTP_REPORT = 18, HTTP_MKACTIVITY = 19, HTTP_CHECKOUT = 20, HTTP_MERGE = 21, HTTP_MSEARCH = 22, HTTP_NOTIFY = 23, HTTP_SUBSCRIBE = 24, HTTP_UNSUBSCRIBE = 25, HTTP_MKCALENDAR = 26,

  };


enum http_parser_type { HTTP_REQUEST, HTTP_RESPONSE, HTTP_BOTH };



enum flags
  { F_CHUNKED = 1 << 0
  , F_CONNECTION_KEEP_ALIVE = 1 << 1
  , F_CONNECTION_CLOSE = 1 << 2
  , F_TRAILING = 1 << 3
  , F_UPGRADE = 1 << 4
  , F_SKIPBODY = 1 << 5
  };

enum http_errno {
  HPE_OK, HPE_CB_message_begin, HPE_CB_url, HPE_CB_header_field, HPE_CB_header_value, HPE_CB_headers_complete, HPE_CB_body, HPE_CB_message_complete, HPE_CB_status, HPE_INVALID_EOF_STATE, HPE_HEADER_OVERFLOW, HPE_CLOSED_CONNECTION, HPE_INVALID_VERSION, HPE_INVALID_STATUS, HPE_INVALID_METHOD, HPE_INVALID_URL, HPE_INVALID_HOST, HPE_INVALID_PORT, HPE_INVALID_PATH, HPE_INVALID_QUERY_STRING, HPE_INVALID_FRAGMENT, HPE_LF_EXPECTED, HPE_INVALID_HEADER_TOKEN, HPE_INVALID_CONTENT_LENGTH, HPE_INVALID_CHUNK_SIZE, HPE_INVALID_CONSTANT, HPE_INVALID_INTERNAL_STATE, HPE_STRICT, HPE_PAUSED, HPE_UNKNOWN,
};







struct http_parser {

  unsigned int type : 2;
  unsigned int flags : 6;
  unsigned int state : 8;
  unsigned int header_state : 8;
  unsigned int index : 8;

  uint32_t nread;
  uint64_t content_length;


  unsigned short http_major;
  unsigned short http_minor;
  unsigned int status_code : 16;
  unsigned int method : 8;
  unsigned int http_errno : 7;






  unsigned int upgrade : 1;


  void *data;
};


struct http_parser_settings {
  http_cb on_message_begin;
  http_data_cb on_url;
  http_data_cb on_status;
  http_data_cb on_header_field;
  http_data_cb on_header_value;
  http_cb on_headers_complete;
  http_data_cb on_body;
  http_cb on_message_complete;
};


enum http_parser_url_fields
  { UF_SCHEMA = 0
  , UF_HOST = 1
  , UF_PORT = 2
  , UF_PATH = 3
  , UF_QUERY = 4
  , UF_FRAGMENT = 5
  , UF_USERINFO = 6
  , UF_MAX = 7
  };

struct http_parser_url {
  uint16_t field_set;
  uint16_t port;

  struct {
    uint16_t off;
    uint16_t len;
  } field_data[UF_MAX];
};

unsigned long http_parser_version(void);

void http_parser_init(http_parser *parser, enum http_parser_type type);


size_t http_parser_execute(http_parser *parser,
                           const http_parser_settings *settings,
                           const char *data,
                           size_t len);

int http_should_keep_alive(const http_parser *parser);


const char *http_method_str(enum http_method m);


const char *http_errno_name(enum http_errno err);


const char *http_errno_description(enum http_errno err);


int http_parser_parse_url(const char *buf, size_t buflen,
                          int is_connect,
                          struct http_parser_url *u);


void http_parser_pause(http_parser *parser, int paused);


int http_body_is_final(const http_parser *parser);








enum state
  { s_dead = 1

  , s_start_req_or_res
  , s_res_or_resp_H
  , s_start_res
  , s_res_H
  , s_res_HT
  , s_res_HTT
  , s_res_HTTP
  , s_res_first_http_major
  , s_res_http_major
  , s_res_first_http_minor
  , s_res_http_minor
  , s_res_first_status_code
  , s_res_status_code
  , s_res_status_start
  , s_res_status
  , s_res_line_almost_done

  , s_start_req

  , s_req_method
  , s_req_spaces_before_url
  , s_req_schema
  , s_req_schema_slash
  , s_req_schema_slash_slash
  , s_req_server_start
  , s_req_server
  , s_req_server_with_at
  , s_req_path
  , s_req_query_string_start
  , s_req_query_string
  , s_req_fragment_start
  , s_req_fragment
  , s_req_http_start
  , s_req_http_H
  , s_req_http_HT
  , s_req_http_HTT
  , s_req_http_HTTP
  , s_req_first_http_major
  , s_req_http_major
  , s_req_first_http_minor
  , s_req_http_minor
  , s_req_line_almost_done

  , s_header_field_start
  , s_header_field
  , s_header_value_discard_ws
  , s_header_value_discard_ws_almost_done
  , s_header_value_discard_lws
  , s_header_value_start
  , s_header_value
  , s_header_value_lws

  , s_header_almost_done

  , s_chunk_size_start
  , s_chunk_size
  , s_chunk_parameters
  , s_chunk_size_almost_done

  , s_headers_almost_done
  , s_headers_done






  , s_chunk_data
  , s_chunk_data_almost_done
  , s_chunk_data_done

  , s_body_identity
  , s_body_identity_eof

  , s_message_done
  };





enum header_states
  { h_general = 0
  , h_C
  , h_CO
  , h_CON

  , h_matching_connection
  , h_matching_proxy_connection
  , h_matching_content_length
  , h_matching_transfer_encoding
  , h_matching_upgrade

  , h_connection
  , h_content_length
  , h_transfer_encoding
  , h_upgrade

  , h_matching_transfer_encoding_chunked
  , h_matching_connection_keep_alive
  , h_matching_connection_close

  , h_transfer_encoding_chunked
  , h_connection_keep_alive
  , h_connection_close
  };

enum http_host_state
  {
    s_http_host_dead = 1
  , s_http_userinfo_start
  , s_http_userinfo
  , s_http_host_start
  , s_http_host_v6_start
  , s_http_host
  , s_http_host_v6
  , s_http_host_v6_end
  , s_http_host_port_start
  , s_http_host_port
};

int http_message_needs_eof(const http_parser *parser);

inline enum state
parse_url_char(enum state s, const char ch)
{







static const uint8_t normal_url_char[32] = {

        0 | 0 | 0 | 0 | 0 | 0 | 0 | 0,

        0 | 0 | 0 | 0 | 0 | 0 | 0 | 0,

        0 | 0 | 0 | 0 | 0 | 0 | 0 | 0,

        0 | 0 | 0 | 0 | 0 | 0 | 0 | 0,

        0 | 2 | 4 | 0 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 0,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 0, };



  if (ch == ' ' || ch == '\r' || ch == '\n') {
    return s_dead;
  }


  if (ch == '\t' || ch == '\f') {
    return s_dead;
  }


  switch (s) {
    case s_req_spaces_before_url:




      if (ch == '/' || ch == '*') {
        return s_req_path;
      }

      if (((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z')) {
        return s_req_schema;
      }

      break;

    case s_req_schema:
      if (((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z')) {
        return s;
      }

      if (ch == ':') {
        return s_req_schema_slash;
      }

      break;

    case s_req_schema_slash:
      if (ch == '/') {
        return s_req_schema_slash_slash;
      }

      break;

    case s_req_schema_slash_slash:
      if (ch == '/') {
        return s_req_server_start;
      }

      break;

    case s_req_server_with_at:
      if (ch == '@') {
        return s_dead;
      }


    case s_req_server_start:
    case s_req_server:
      if (ch == '/') {
        return s_req_path;
      }

      if (ch == '?') {
        return s_req_query_string_start;
      }

      if (ch == '@') {
        return s_req_server_with_at;
      }

      if (((((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z') || ((ch) >= '0' && (ch) <= '9')) || ((ch) == '-' || (ch) == '_' || (ch) == '.' || (ch) == '!' || (ch) == '~' || (ch) == '*' || (ch) == '\'' || (ch) == '(' || (ch) == ')') || (ch) == '%' || (ch) == ';' || (ch) == ':' || (ch) == '&' || (ch) == '=' || (ch) == '+' || (ch) == '$' || (ch) == ',') || ch == '[' || ch == ']') {
        return s_req_server;
      }

      break;

    case s_req_path:
      if (((!!((unsigned int) (normal_url_char)[(unsigned int) ((unsigned char)ch) >> 3] & (1 << ((unsigned int) ((unsigned char)ch) & 7)))))) {
        return s;
      }

      switch (ch) {
        case '?':
          return s_req_query_string_start;

        case '#':
          return s_req_fragment_start;
      }

      break;

    case s_req_query_string_start:
    case s_req_query_string:
      if (((!!((unsigned int) (normal_url_char)[(unsigned int) ((unsigned char)ch) >> 3] & (1 << ((unsigned int) ((unsigned char)ch) & 7)))))) {
        return s_req_query_string;
      }

      switch (ch) {
        case '?':

          return s_req_query_string;

        case '#':
          return s_req_fragment_start;
      }

      break;

    case s_req_fragment_start:
      if (((!!((unsigned int) (normal_url_char)[(unsigned int) ((unsigned char)ch) >> 3] & (1 << ((unsigned int) ((unsigned char)ch) & 7)))))) {
        return s_req_fragment;
      }

      switch (ch) {
        case '?':
          return s_req_fragment;

        case '#':
          return s;
      }

      break;

    case s_req_fragment:
      if (((!!((unsigned int) (normal_url_char)[(unsigned int) ((unsigned char)ch) >> 3] & (1 << ((unsigned int) ((unsigned char)ch) & 7)))))) {
        return s;
      }

      switch (ch) {
        case '?':
        case '#':
          return s;
      }

      break;

    default:
      break;
  }


  return s_dead;
}

inline size_t http_parser_execute (http_parser *parser,
                            const http_parser_settings *settings,
                            const char *data,
                            size_t len)
{
static const char *method_strings[] =
  {

  "DELETE", "GET", "HEAD", "POST", "PUT", "CONNECT", "OPTIONS", "TRACE", "PATCH", "PURGE", "COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND", "PROPPATCH", "SEARCH", "UNLOCK", "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE", "M-SEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "MKCALENDAR",

  };

static const char tokens[256] = {

        0, 0, 0, 0, 0, 0, 0, 0,

        0, 0, 0, 0, 0, 0, 0, 0,

        0, 0, 0, 0, 0, 0, 0, 0,

        0, 0, 0, 0, 0, 0, 0, 0,

        0, '!', 0, '#', '$', '%', '&', '\'',

        0, 0, '*', '+', 0, '-', '.', 0,

       '0', '1', '2', '3', '4', '5', '6', '7',

       '8', '9', 0, 0, 0, 0, 0, 0,

        0, 'a', 'b', 'c', 'd', 'e', 'f', 'g',

       'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',

       'p', 'q', 'r', 's', 't', 'u', 'v', 'w',

       'x', 'y', 'z', 0, 0, 0, '^', '_',

       '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g',

       'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',

       'p', 'q', 'r', 's', 't', 'u', 'v', 'w',

       'x', 'y', 'z', 0, '|', 0, '~', 0 };


static const int8_t unhex[256] =
  {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  , 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1
  ,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  };



  char c, ch;
  int8_t unhex_val;
  const char *p = data;
  const char *header_field_mark = 0;
  const char *header_value_mark = 0;
  const char *url_mark = 0;
  const char *body_mark = 0;
  const char *status_mark = 0;


  if (((enum http_errno) (parser)->http_errno) != HPE_OK) {
    return 0;
  }

  if (len == 0) {
    switch (parser->state) {
      case s_body_identity_eof:



        do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } } while (0);
        return 0;

      case s_dead:
      case s_start_req_or_res:
      case s_start_res:
      case s_start_req:
        return 0;

      default:
        do { parser->http_errno = (HPE_INVALID_EOF_STATE); } while(0);
        return 1;
    }
  }


  if (parser->state == s_header_field)
    header_field_mark = data;
  if (parser->state == s_header_value)
    header_value_mark = data;
  switch (parser->state) {
  case s_req_path:
  case s_req_schema:
  case s_req_schema_slash:
  case s_req_schema_slash_slash:
  case s_req_server_start:
  case s_req_server:
  case s_req_server_with_at:
  case s_req_query_string_start:
  case s_req_query_string:
  case s_req_fragment_start:
  case s_req_fragment:
    url_mark = data;
    break;
  case s_res_status:
    status_mark = data;
    break;
  }

  for (p=data; p != data + len; p++) {
    ch = *p;

    if ((parser->state <= s_headers_done)) {
      ++parser->nread;

      if (parser->nread > ((80*1024))) {
        do { parser->http_errno = (HPE_HEADER_OVERFLOW); } while(0);
        goto error;
      }
    }

    reexecute_byte:
    switch (parser->state) {

      case s_dead:



        if (ch == '\r' || ch == '\n')
          break;

        do { parser->http_errno = (HPE_CLOSED_CONNECTION); } while(0);
        goto error;

      case s_start_req_or_res:
      {
        if (ch == '\r' || ch == '\n')
          break;
        parser->flags = 0;
        parser->content_length = ((uint64_t) -1);

        if (ch == 'H') {
          parser->state = s_res_or_resp_H;

          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_begin) { if (0 != settings->on_message_begin(parser)) { do { parser->http_errno = (HPE_CB_message_begin); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
        } else {
          parser->type = HTTP_REQUEST;
          parser->state = s_start_req;
          goto reexecute_byte;
        }

        break;
      }

      case s_res_or_resp_H:
        if (ch == 'T') {
          parser->type = HTTP_RESPONSE;
          parser->state = s_res_HT;
        } else {
          if (ch != 'E') {
            do { parser->http_errno = (HPE_INVALID_CONSTANT); } while(0);
            goto error;
          }

          parser->type = HTTP_REQUEST;
          parser->method = HTTP_HEAD;
          parser->index = 2;
          parser->state = s_req_method;
        }
        break;

      case s_start_res:
      {
        parser->flags = 0;
        parser->content_length = ((uint64_t) -1);

        switch (ch) {
          case 'H':
            parser->state = s_res_H;
            break;

          case '\r':
          case '\n':
            break;

          default:
            do { parser->http_errno = (HPE_INVALID_CONSTANT); } while(0);
            goto error;
        }

        do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_begin) { if (0 != settings->on_message_begin(parser)) { do { parser->http_errno = (HPE_CB_message_begin); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
        break;
      }

      case s_res_H:
        do { if (ch != 'T') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_res_HT;
        break;

      case s_res_HT:
        do { if (ch != 'T') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_res_HTT;
        break;

      case s_res_HTT:
        do { if (ch != 'P') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_res_HTTP;
        break;

      case s_res_HTTP:
        do { if (ch != '/') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_res_first_http_major;
        break;

      case s_res_first_http_major:
        if (ch < '0' || ch > '9') {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_major = ch - '0';
        parser->state = s_res_http_major;
        break;


      case s_res_http_major:
      {
        if (ch == '.') {
          parser->state = s_res_first_http_minor;
          break;
        }

        if (!((ch) >= '0' && (ch) <= '9')) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_major *= 10;
        parser->http_major += ch - '0';

        if (parser->http_major > 999) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        break;
      }


      case s_res_first_http_minor:
        if (!((ch) >= '0' && (ch) <= '9')) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_minor = ch - '0';
        parser->state = s_res_http_minor;
        break;


      case s_res_http_minor:
      {
        if (ch == ' ') {
          parser->state = s_res_first_status_code;
          break;
        }

        if (!((ch) >= '0' && (ch) <= '9')) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_minor *= 10;
        parser->http_minor += ch - '0';

        if (parser->http_minor > 999) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        break;
      }

      case s_res_first_status_code:
      {
        if (!((ch) >= '0' && (ch) <= '9')) {
          if (ch == ' ') {
            break;
          }

          do { parser->http_errno = (HPE_INVALID_STATUS); } while(0);
          goto error;
        }
        parser->status_code = ch - '0';
        parser->state = s_res_status_code;
        break;
      }

      case s_res_status_code:
      {
        if (!((ch) >= '0' && (ch) <= '9')) {
          switch (ch) {
            case ' ':
              parser->state = s_res_status_start;
              break;
            case '\r':
              parser->state = s_res_line_almost_done;
              break;
            case '\n':
              parser->state = s_header_field_start;
              break;
            default:
              do { parser->http_errno = (HPE_INVALID_STATUS); } while(0);
              goto error;
          }
          break;
        }

        parser->status_code *= 10;
        parser->status_code += ch - '0';

        if (parser->status_code > 999) {
          do { parser->http_errno = (HPE_INVALID_STATUS); } while(0);
          goto error;
        }

        break;
      }

      case s_res_status_start:
      {
        if (ch == '\r') {
          parser->state = s_res_line_almost_done;
          break;
        }

        if (ch == '\n') {
          parser->state = s_header_field_start;
          break;
        }

        do { if (!status_mark) { status_mark = p; } } while (0);
        parser->state = s_res_status;
        parser->index = 0;
        break;
      }

      case s_res_status:
        if (ch == '\r') {
          parser->state = s_res_line_almost_done;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (status_mark) { if (settings->on_status) { if (0 != settings->on_status(parser, status_mark, (p - status_mark))) { do { parser->http_errno = (HPE_CB_status); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } status_mark = NULL; } } while (0);
          break;
        }

        if (ch == '\n') {
          parser->state = s_header_field_start;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (status_mark) { if (settings->on_status) { if (0 != settings->on_status(parser, status_mark, (p - status_mark))) { do { parser->http_errno = (HPE_CB_status); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } status_mark = NULL; } } while (0);
          break;
        }

        break;

      case s_res_line_almost_done:
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_header_field_start;
        break;

      case s_start_req:
      {
        if (ch == '\r' || ch == '\n')
          break;
        parser->flags = 0;
        parser->content_length = ((uint64_t) -1);

        if (!((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z')) {
          do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
          goto error;
        }

        parser->method = (enum http_method) 0;
        parser->index = 1;
        switch (ch) {
          case 'C': parser->method = HTTP_CONNECT; break;
          case 'D': parser->method = HTTP_DELETE; break;
          case 'G': parser->method = HTTP_GET; break;
          case 'H': parser->method = HTTP_HEAD; break;
          case 'L': parser->method = HTTP_LOCK; break;
          case 'M': parser->method = HTTP_MKCOL; break;
          case 'N': parser->method = HTTP_NOTIFY; break;
          case 'O': parser->method = HTTP_OPTIONS; break;
          case 'P': parser->method = HTTP_POST;

            break;
          case 'R': parser->method = HTTP_REPORT; break;
          case 'S': parser->method = HTTP_SUBSCRIBE; break;
          case 'T': parser->method = HTTP_TRACE; break;
          case 'U': parser->method = HTTP_UNLOCK; break;
          default:
            do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
            goto error;
        }
        parser->state = s_req_method;

        do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_begin) { if (0 != settings->on_message_begin(parser)) { do { parser->http_errno = (HPE_CB_message_begin); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);

        break;
      }

      case s_req_method:
      {
        const char *matcher;
        if (ch == '\0') {
          do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
          goto error;
        }

        matcher = method_strings[parser->method];
        if (ch == ' ' && matcher[parser->index] == '\0') {
          parser->state = s_req_spaces_before_url;
        } else if (ch == matcher[parser->index]) {
          ;
        } else if (parser->method == HTTP_CONNECT) {
          if (parser->index == 1 && ch == 'H') {
            parser->method = HTTP_CHECKOUT;
          } else if (parser->index == 2 && ch == 'P') {
            parser->method = HTTP_COPY;
          } else {
            do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
            goto error;
          }
        } else if (parser->method == HTTP_MKCOL) {
          if (parser->index == 1 && ch == 'O') {
            parser->method = HTTP_MOVE;
          } else if (parser->index == 1 && ch == 'E') {
            parser->method = HTTP_MERGE;
          } else if (parser->index == 1 && ch == '-') {
            parser->method = HTTP_MSEARCH;
          } else if (parser->index == 2 && ch == 'A') {
            parser->method = HTTP_MKACTIVITY;
          } else if (parser->index == 3 && ch == 'A') {
            parser->method = HTTP_MKCALENDAR;
          } else {
            do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
            goto error;
          }
        } else if (parser->method == HTTP_SUBSCRIBE) {
          if (parser->index == 1 && ch == 'E') {
            parser->method = HTTP_SEARCH;
          } else {
            do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
            goto error;
          }
        } else if (parser->index == 1 && parser->method == HTTP_POST) {
          if (ch == 'R') {
            parser->method = HTTP_PROPFIND;
          } else if (ch == 'U') {
            parser->method = HTTP_PUT;
          } else if (ch == 'A') {
            parser->method = HTTP_PATCH;
          } else {
            do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
            goto error;
          }
        } else if (parser->index == 2) {
          if (parser->method == HTTP_PUT) {
            if (ch == 'R') {
              parser->method = HTTP_PURGE;
            } else {
              do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
              goto error;
            }
          } else if (parser->method == HTTP_UNLOCK) {
            if (ch == 'S') {
              parser->method = HTTP_UNSUBSCRIBE;
            } else {
              do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
              goto error;
            }
          } else {
            do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
            goto error;
          }
        } else if (parser->index == 4 && parser->method == HTTP_PROPFIND && ch == 'P') {
          parser->method = HTTP_PROPPATCH;
        } else {
          do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
          goto error;
        }

        ++parser->index;
        break;
      }

      case s_req_spaces_before_url:
      {
        if (ch == ' ') break;

        do { if (!url_mark) { url_mark = p; } } while (0);
        if (parser->method == HTTP_CONNECT) {
          parser->state = s_req_server_start;
        }

        parser->state = parse_url_char((enum state)parser->state, ch);
        if (parser->state == s_dead) {
          do { parser->http_errno = (HPE_INVALID_URL); } while(0);
          goto error;
        }

        break;
      }

      case s_req_schema:
      case s_req_schema_slash:
      case s_req_schema_slash_slash:
      case s_req_server_start:
      {
        switch (ch) {

          case ' ':
          case '\r':
          case '\n':
            do { parser->http_errno = (HPE_INVALID_URL); } while(0);
            goto error;
          default:
            parser->state = parse_url_char((enum state)parser->state, ch);
            if (parser->state == s_dead) {
              do { parser->http_errno = (HPE_INVALID_URL); } while(0);
              goto error;
            }
        }

        break;
      }

      case s_req_server:
      case s_req_server_with_at:
      case s_req_path:
      case s_req_query_string_start:
      case s_req_query_string:
      case s_req_fragment_start:
      case s_req_fragment:
      {
        switch (ch) {
          case ' ':
            parser->state = s_req_http_start;
            do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (url_mark) { if (settings->on_url) { if (0 != settings->on_url(parser, url_mark, (p - url_mark))) { do { parser->http_errno = (HPE_CB_url); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } url_mark = NULL; } } while (0);
            break;
          case '\r':
          case '\n':
            parser->http_major = 0;
            parser->http_minor = 9;
            parser->state = (ch == '\r') ?
              s_req_line_almost_done :
              s_header_field_start;
            do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (url_mark) { if (settings->on_url) { if (0 != settings->on_url(parser, url_mark, (p - url_mark))) { do { parser->http_errno = (HPE_CB_url); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } url_mark = NULL; } } while (0);
            break;
          default:
            parser->state = parse_url_char((enum state)parser->state, ch);
            if (parser->state == s_dead) {
              do { parser->http_errno = (HPE_INVALID_URL); } while(0);
              goto error;
            }
        }
        break;
      }

      case s_req_http_start:
        switch (ch) {
          case 'H':
            parser->state = s_req_http_H;
            break;
          case ' ':
            break;
          default:
            do { parser->http_errno = (HPE_INVALID_CONSTANT); } while(0);
            goto error;
        }
        break;

      case s_req_http_H:
        do { if (ch != 'T') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_req_http_HT;
        break;

      case s_req_http_HT:
        do { if (ch != 'T') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_req_http_HTT;
        break;

      case s_req_http_HTT:
        do { if (ch != 'P') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_req_http_HTTP;
        break;

      case s_req_http_HTTP:
        do { if (ch != '/') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_req_first_http_major;
        break;


      case s_req_first_http_major:
        if (ch < '1' || ch > '9') {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_major = ch - '0';
        parser->state = s_req_http_major;
        break;


      case s_req_http_major:
      {
        if (ch == '.') {
          parser->state = s_req_first_http_minor;
          break;
        }

        if (!((ch) >= '0' && (ch) <= '9')) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_major *= 10;
        parser->http_major += ch - '0';

        if (parser->http_major > 999) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        break;
      }


      case s_req_first_http_minor:
        if (!((ch) >= '0' && (ch) <= '9')) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_minor = ch - '0';
        parser->state = s_req_http_minor;
        break;


      case s_req_http_minor:
      {
        if (ch == '\r') {
          parser->state = s_req_line_almost_done;
          break;
        }

        if (ch == '\n') {
          parser->state = s_header_field_start;
          break;
        }



        if (!((ch) >= '0' && (ch) <= '9')) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_minor *= 10;
        parser->http_minor += ch - '0';

        if (parser->http_minor > 999) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        break;
      }


      case s_req_line_almost_done:
      {
        if (ch != '\n') {
          do { parser->http_errno = (HPE_LF_EXPECTED); } while(0);
          goto error;
        }

        parser->state = s_header_field_start;
        break;
      }

      case s_header_field_start:
      {
        if (ch == '\r') {
          parser->state = s_headers_almost_done;
          break;
        }

        if (ch == '\n') {


          parser->state = s_headers_almost_done;
          goto reexecute_byte;
        }

        c = (tokens[(unsigned char)ch]);

        if (!c) {
          do { parser->http_errno = (HPE_INVALID_HEADER_TOKEN); } while(0);
          goto error;
        }

        do { if (!header_field_mark) { header_field_mark = p; } } while (0);

        parser->index = 0;
        parser->state = s_header_field;

        switch (c) {
          case 'c':
            parser->header_state = h_C;
            break;

          case 'p':
            parser->header_state = h_matching_proxy_connection;
            break;

          case 't':
            parser->header_state = h_matching_transfer_encoding;
            break;

          case 'u':
            parser->header_state = h_matching_upgrade;
            break;

          default:
            parser->header_state = h_general;
            break;
        }
        break;
      }

      case s_header_field:
      {
        c = (tokens[(unsigned char)ch]);

        if (c) {
          switch (parser->header_state) {
            case h_general:
              break;

            case h_C:
              parser->index++;
              parser->header_state = (c == 'o' ? h_CO : h_general);
              break;

            case h_CO:
              parser->index++;
              parser->header_state = (c == 'n' ? h_CON : h_general);
              break;

            case h_CON:
              parser->index++;
              switch (c) {
                case 'n':
                  parser->header_state = h_matching_connection;
                  break;
                case 't':
                  parser->header_state = h_matching_content_length;
                  break;
                default:
                  parser->header_state = h_general;
                  break;
              }
              break;



            case h_matching_connection:
              parser->index++;
              if (parser->index > sizeof("connection")-1
                  || c != "connection"[parser->index]) {
                parser->header_state = h_general;
              } else if (parser->index == sizeof("connection")-2) {
                parser->header_state = h_connection;
              }
              break;



            case h_matching_proxy_connection:
              parser->index++;
              if (parser->index > sizeof("proxy-connection")-1
                  || c != "proxy-connection"[parser->index]) {
                parser->header_state = h_general;
              } else if (parser->index == sizeof("proxy-connection")-2) {
                parser->header_state = h_connection;
              }
              break;



            case h_matching_content_length:
              parser->index++;
              if (parser->index > sizeof("content-length")-1
                  || c != "content-length"[parser->index]) {
                parser->header_state = h_general;
              } else if (parser->index == sizeof("content-length")-2) {
                parser->header_state = h_content_length;
              }
              break;



            case h_matching_transfer_encoding:
              parser->index++;
              if (parser->index > sizeof("transfer-encoding")-1
                  || c != "transfer-encoding"[parser->index]) {
                parser->header_state = h_general;
              } else if (parser->index == sizeof("transfer-encoding")-2) {
                parser->header_state = h_transfer_encoding;
              }
              break;



            case h_matching_upgrade:
              parser->index++;
              if (parser->index > sizeof("upgrade")-1
                  || c != "upgrade"[parser->index]) {
                parser->header_state = h_general;
              } else if (parser->index == sizeof("upgrade")-2) {
                parser->header_state = h_upgrade;
              }
              break;

            case h_connection:
            case h_content_length:
            case h_transfer_encoding:
            case h_upgrade:
              if (ch != ' ') parser->header_state = h_general;
              break;

            default:
              assert(0 && "Unknown header_state");
              break;
          }
          break;
        }

        if (ch == ':') {
          parser->state = s_header_value_discard_ws;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_field_mark) { if (settings->on_header_field) { if (0 != settings->on_header_field(parser, header_field_mark, (p - header_field_mark))) { do { parser->http_errno = (HPE_CB_header_field); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } header_field_mark = NULL; } } while (0);
          break;
        }

        if (ch == '\r') {
          parser->state = s_header_almost_done;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_field_mark) { if (settings->on_header_field) { if (0 != settings->on_header_field(parser, header_field_mark, (p - header_field_mark))) { do { parser->http_errno = (HPE_CB_header_field); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } header_field_mark = NULL; } } while (0);
          break;
        }

        if (ch == '\n') {
          parser->state = s_header_field_start;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_field_mark) { if (settings->on_header_field) { if (0 != settings->on_header_field(parser, header_field_mark, (p - header_field_mark))) { do { parser->http_errno = (HPE_CB_header_field); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } header_field_mark = NULL; } } while (0);
          break;
        }

        do { parser->http_errno = (HPE_INVALID_HEADER_TOKEN); } while(0);
        goto error;
      }

      case s_header_value_discard_ws:
        if (ch == ' ' || ch == '\t') break;

        if (ch == '\r') {
          parser->state = s_header_value_discard_ws_almost_done;
          break;
        }

        if (ch == '\n') {
          parser->state = s_header_value_discard_lws;
          break;
        }



      case s_header_value_start:
      {
        do { if (!header_value_mark) { header_value_mark = p; } } while (0);

        parser->state = s_header_value;
        parser->index = 0;

        c = (unsigned char)(ch | 0x20);

        switch (parser->header_state) {
          case h_upgrade:
            parser->flags |= F_UPGRADE;
            parser->header_state = h_general;
            break;

          case h_transfer_encoding:

            if ('c' == c) {
              parser->header_state = h_matching_transfer_encoding_chunked;
            } else {
              parser->header_state = h_general;
            }
            break;

          case h_content_length:
            if (!((ch) >= '0' && (ch) <= '9')) {
              do { parser->http_errno = (HPE_INVALID_CONTENT_LENGTH); } while(0);
              goto error;
            }

            parser->content_length = ch - '0';
            break;

          case h_connection:

            if (c == 'k') {
              parser->header_state = h_matching_connection_keep_alive;

            } else if (c == 'c') {
              parser->header_state = h_matching_connection_close;
            } else {
              parser->header_state = h_general;
            }
            break;

          default:
            parser->header_state = h_general;
            break;
        }
        break;
      }

      case s_header_value:
      {

        if (ch == '\r') {
          parser->state = s_header_almost_done;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_value_mark) { if (settings->on_header_value) { if (0 != settings->on_header_value(parser, header_value_mark, (p - header_value_mark))) { do { parser->http_errno = (HPE_CB_header_value); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } header_value_mark = NULL; } } while (0);
          break;
        }

        if (ch == '\n') {
          parser->state = s_header_almost_done;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_value_mark) { if (settings->on_header_value) { if (0 != settings->on_header_value(parser, header_value_mark, (p - header_value_mark))) { do { parser->http_errno = (HPE_CB_header_value); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } header_value_mark = NULL; } } while (0);
          goto reexecute_byte;
        }

        c = (unsigned char)(ch | 0x20);

        switch (parser->header_state) {
          case h_general:
            break;

          case h_connection:
          case h_transfer_encoding:
            assert(0 && "Shouldn't get here.");
            break;

          case h_content_length:
          {
            uint64_t t;

            if (ch == ' ') break;

            if (!((ch) >= '0' && (ch) <= '9')) {
              do { parser->http_errno = (HPE_INVALID_CONTENT_LENGTH); } while(0);
              goto error;
            }

            t = parser->content_length;
            t *= 10;
            t += ch - '0';


            if ((((uint64_t) -1) - 10) / 10 < parser->content_length) {
              do { parser->http_errno = (HPE_INVALID_CONTENT_LENGTH); } while(0);
              goto error;
            }

            parser->content_length = t;
            break;
          }


          case h_matching_transfer_encoding_chunked:
            parser->index++;
            if (parser->index > sizeof("chunked")-1
                || c != "chunked"[parser->index]) {
              parser->header_state = h_general;
            } else if (parser->index == sizeof("chunked")-2) {
              parser->header_state = h_transfer_encoding_chunked;
            }
            break;


          case h_matching_connection_keep_alive:
            parser->index++;
            if (parser->index > sizeof("keep-alive")-1
                || c != "keep-alive"[parser->index]) {
              parser->header_state = h_general;
            } else if (parser->index == sizeof("keep-alive")-2) {
              parser->header_state = h_connection_keep_alive;
            }
            break;


          case h_matching_connection_close:
            parser->index++;
            if (parser->index > sizeof("close")-1 || c != "close"[parser->index]) {
              parser->header_state = h_general;
            } else if (parser->index == sizeof("close")-2) {
              parser->header_state = h_connection_close;
            }
            break;

          case h_transfer_encoding_chunked:
          case h_connection_keep_alive:
          case h_connection_close:
            if (ch != ' ') parser->header_state = h_general;
            break;

          default:
            parser->state = s_header_value;
            parser->header_state = h_general;
            break;
        }
        break;
      }

      case s_header_almost_done:
      {
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);

        parser->state = s_header_value_lws;
        break;
      }

      case s_header_value_lws:
      {
        if (ch == ' ' || ch == '\t') {
          parser->state = s_header_value_start;
          goto reexecute_byte;
        }


        switch (parser->header_state) {
          case h_connection_keep_alive:
            parser->flags |= F_CONNECTION_KEEP_ALIVE;
            break;
          case h_connection_close:
            parser->flags |= F_CONNECTION_CLOSE;
            break;
          case h_transfer_encoding_chunked:
            parser->flags |= F_CHUNKED;
            break;
          default:
            break;
        }

        parser->state = s_header_field_start;
        goto reexecute_byte;
      }

      case s_header_value_discard_ws_almost_done:
      {
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_header_value_discard_lws;
        break;
      }

      case s_header_value_discard_lws:
      {
        if (ch == ' ' || ch == '\t') {
          parser->state = s_header_value_discard_ws;
          break;
        } else {

          do { if (!header_value_mark) { header_value_mark = p; } } while (0);
          parser->state = s_header_field_start;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_value_mark) { if (settings->on_header_value) { if (0 != settings->on_header_value(parser, header_value_mark, (p - header_value_mark))) { do { parser->http_errno = (HPE_CB_header_value); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } header_value_mark = NULL; } } while (0);
          goto reexecute_byte;
        }
      }

      case s_headers_almost_done:
      {
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);

        if (parser->flags & F_TRAILING) {

          parser->state = (http_should_keep_alive(parser) ? (parser->type == HTTP_REQUEST ? s_start_req : s_start_res) : s_dead);
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
          break;
        }

        parser->state = s_headers_done;


        parser->upgrade =
          (parser->flags & F_UPGRADE || parser->method == HTTP_CONNECT);

        if (settings->on_headers_complete) {
          switch (settings->on_headers_complete(parser)) {
            case 0:
              break;

            case 1:
              parser->flags |= F_SKIPBODY;
              break;

            default:
              do { parser->http_errno = (HPE_CB_headers_complete); } while(0);
              return p - data;
          }
        }

        if (((enum http_errno) (parser)->http_errno) != HPE_OK) {
          return p - data;
        }

        goto reexecute_byte;
      }

      case s_headers_done:
      {
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);

        parser->nread = 0;


        if (parser->upgrade) {
          parser->state = (http_should_keep_alive(parser) ? (parser->type == HTTP_REQUEST ? s_start_req : s_start_res) : s_dead);
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
          return (p - data) + 1;
        }

        if (parser->flags & F_SKIPBODY) {
          parser->state = (http_should_keep_alive(parser) ? (parser->type == HTTP_REQUEST ? s_start_req : s_start_res) : s_dead);
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
        } else if (parser->flags & F_CHUNKED) {

          parser->state = s_chunk_size_start;
        } else {
          if (parser->content_length == 0) {

            parser->state = (http_should_keep_alive(parser) ? (parser->type == HTTP_REQUEST ? s_start_req : s_start_res) : s_dead);
            do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
          } else if (parser->content_length != ((uint64_t) -1)) {

            parser->state = s_body_identity;
          } else {
            if (parser->type == HTTP_REQUEST ||
                !http_message_needs_eof(parser)) {

              parser->state = (http_should_keep_alive(parser) ? (parser->type == HTTP_REQUEST ? s_start_req : s_start_res) : s_dead);
              do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
            } else {

              parser->state = s_body_identity_eof;
            }
          }
        }

        break;
      }

      case s_body_identity:
      {
        uint64_t to_read = ((parser->content_length) < ((uint64_t) ((data + len) - p)) ? (parser->content_length) : ((uint64_t) ((data + len) - p)))
                                                             ;

        assert(parser->content_length != 0
            && parser->content_length != ((uint64_t) -1));






        do { if (!body_mark) { body_mark = p; } } while (0);
        parser->content_length -= to_read;
        p += to_read - 1;

        if (parser->content_length == 0) {
          parser->state = s_message_done;

          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (body_mark) { if (settings->on_body) { if (0 != settings->on_body(parser, body_mark, (p - body_mark + 1))) { do { parser->http_errno = (HPE_CB_body); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } body_mark = NULL; } } while (0);
          goto reexecute_byte;
        }

        break;
      }


      case s_body_identity_eof:
        do { if (!body_mark) { body_mark = p; } } while (0);
        p = data + len - 1;

        break;

      case s_message_done:
        parser->state = (http_should_keep_alive(parser) ? (parser->type == HTTP_REQUEST ? s_start_req : s_start_res) : s_dead);
        do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
        break;

      case s_chunk_size_start:
      {
        assert(parser->nread == 1);
        assert(parser->flags & F_CHUNKED);

        unhex_val = unhex[(unsigned char)ch];
        if (unhex_val == -1) {
          do { parser->http_errno = (HPE_INVALID_CHUNK_SIZE); } while(0);
          goto error;
        }

        parser->content_length = unhex_val;
        parser->state = s_chunk_size;
        break;
      }

      case s_chunk_size:
      {
        uint64_t t;

        assert(parser->flags & F_CHUNKED);

        if (ch == '\r') {
          parser->state = s_chunk_size_almost_done;
          break;
        }

        unhex_val = unhex[(unsigned char)ch];

        if (unhex_val == -1) {
          if (ch == ';' || ch == ' ') {
            parser->state = s_chunk_parameters;
            break;
          }

          do { parser->http_errno = (HPE_INVALID_CHUNK_SIZE); } while(0);
          goto error;
        }

        t = parser->content_length;
        t *= 16;
        t += unhex_val;


        if ((((uint64_t) -1) - 16) / 16 < parser->content_length) {
          do { parser->http_errno = (HPE_INVALID_CONTENT_LENGTH); } while(0);
          goto error;
        }

        parser->content_length = t;
        break;
      }

      case s_chunk_parameters:
      {
        assert(parser->flags & F_CHUNKED);

        if (ch == '\r') {
          parser->state = s_chunk_size_almost_done;
          break;
        }
        break;
      }

      case s_chunk_size_almost_done:
      {
        assert(parser->flags & F_CHUNKED);
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);

        parser->nread = 0;

        if (parser->content_length == 0) {
          parser->flags |= F_TRAILING;
          parser->state = s_header_field_start;
        } else {
          parser->state = s_chunk_data;
        }
        break;
      }

      case s_chunk_data:
      {
        uint64_t to_read = ((parser->content_length) < ((uint64_t) ((data + len) - p)) ? (parser->content_length) : ((uint64_t) ((data + len) - p)))
                                                             ;

        assert(parser->flags & F_CHUNKED);
        assert(parser->content_length != 0
            && parser->content_length != ((uint64_t) -1));




        do { if (!body_mark) { body_mark = p; } } while (0);
        parser->content_length -= to_read;
        p += to_read - 1;

        if (parser->content_length == 0) {
          parser->state = s_chunk_data_almost_done;
        }

        break;
      }

      case s_chunk_data_almost_done:
        assert(parser->flags & F_CHUNKED);
        assert(parser->content_length == 0);
        do { if (ch != '\r') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_chunk_data_done;
        do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (body_mark) { if (settings->on_body) { if (0 != settings->on_body(parser, body_mark, (p - body_mark))) { do { parser->http_errno = (HPE_CB_body); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } body_mark = NULL; } } while (0);
        break;

      case s_chunk_data_done:
        assert(parser->flags & F_CHUNKED);
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->nread = 0;
        parser->state = s_chunk_size_start;
        break;

      default:
        assert(0 && "unhandled state");
        do { parser->http_errno = (HPE_INVALID_INTERNAL_STATE); } while(0);
        goto error;
    }
  }

  assert(((header_field_mark ? 1 : 0) +
          (header_value_mark ? 1 : 0) +
          (url_mark ? 1 : 0) +
          (body_mark ? 1 : 0) +
          (status_mark ? 1 : 0)) <= 1);

  do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_field_mark) { if (settings->on_header_field) { if (0 != settings->on_header_field(parser, header_field_mark, (p - header_field_mark))) { do { parser->http_errno = (HPE_CB_header_field); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } header_field_mark = NULL; } } while (0);
  do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_value_mark) { if (settings->on_header_value) { if (0 != settings->on_header_value(parser, header_value_mark, (p - header_value_mark))) { do { parser->http_errno = (HPE_CB_header_value); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } header_value_mark = NULL; } } while (0);
  do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (url_mark) { if (settings->on_url) { if (0 != settings->on_url(parser, url_mark, (p - url_mark))) { do { parser->http_errno = (HPE_CB_url); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } url_mark = NULL; } } while (0);
  do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (body_mark) { if (settings->on_body) { if (0 != settings->on_body(parser, body_mark, (p - body_mark))) { do { parser->http_errno = (HPE_CB_body); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } body_mark = NULL; } } while (0);
  do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (status_mark) { if (settings->on_status) { if (0 != settings->on_status(parser, status_mark, (p - status_mark))) { do { parser->http_errno = (HPE_CB_status); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } status_mark = NULL; } } while (0);

  return len;

error:
  if (((enum http_errno) (parser)->http_errno) == HPE_OK) {
    do { parser->http_errno = (HPE_UNKNOWN); } while(0);
  }

  return (p - data);
}



inline int
http_message_needs_eof (const http_parser *parser)
{
  if (parser->type == HTTP_REQUEST) {
    return 0;
  }


  if (parser->status_code / 100 == 1 ||
      parser->status_code == 204 ||
      parser->status_code == 304 ||
      parser->flags & F_SKIPBODY) {
    return 0;
  }

  if ((parser->flags & F_CHUNKED) || parser->content_length != ((uint64_t) -1)) {
    return 0;
  }

  return 1;
}


inline int
http_should_keep_alive (const http_parser *parser)
{
  if (parser->http_major > 0 && parser->http_minor > 0) {

    if (parser->flags & F_CONNECTION_CLOSE) {
      return 0;
    }
  } else {

    if (!(parser->flags & F_CONNECTION_KEEP_ALIVE)) {
      return 0;
    }
  }

  return !http_message_needs_eof(parser);
}


inline const char *
http_method_str (enum http_method m)
{
static const char *method_strings[] =
  {

  "DELETE", "GET", "HEAD", "POST", "PUT", "CONNECT", "OPTIONS", "TRACE", "PATCH", "PURGE", "COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND", "PROPPATCH", "SEARCH", "UNLOCK", "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE", "M-SEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "MKCALENDAR",

  };
  return ((unsigned int) (m) < (sizeof(method_strings) / sizeof((method_strings)[0])) ? (method_strings)[(m)] : ("<unknown>"));
}


inline void
http_parser_init (http_parser *parser, enum http_parser_type t)
{
  void *data = parser->data;
  memset(parser, 0, sizeof(*parser));
  parser->data = data;
  parser->type = t;
  parser->state = (t == HTTP_REQUEST ? s_start_req : (t == HTTP_RESPONSE ? s_start_res : s_start_req_or_res));
  parser->http_errno = HPE_OK;
}

inline const char *
http_errno_name(enum http_errno err) {


static struct {
  const char *name;
  const char *description;
} http_strerror_tab[] = {
  { "HPE_" "OK", "success" }, { "HPE_" "CB_message_begin", "the on_message_begin callback failed" }, { "HPE_" "CB_url", "the on_url callback failed" }, { "HPE_" "CB_header_field", "the on_header_field callback failed" }, { "HPE_" "CB_header_value", "the on_header_value callback failed" }, { "HPE_" "CB_headers_complete", "the on_headers_complete callback failed" }, { "HPE_" "CB_body", "the on_body callback failed" }, { "HPE_" "CB_message_complete", "the on_message_complete callback failed" }, { "HPE_" "CB_status", "the on_status callback failed" }, { "HPE_" "INVALID_EOF_STATE", "stream ended at an unexpected time" }, { "HPE_" "HEADER_OVERFLOW", "too many header bytes seen; overflow detected" }, { "HPE_" "CLOSED_CONNECTION", "data received after completed connection: close message" }, { "HPE_" "INVALID_VERSION", "invalid HTTP version" }, { "HPE_" "INVALID_STATUS", "invalid HTTP status code" }, { "HPE_" "INVALID_METHOD", "invalid HTTP method" }, { "HPE_" "INVALID_URL", "invalid URL" }, { "HPE_" "INVALID_HOST", "invalid host" }, { "HPE_" "INVALID_PORT", "invalid port" }, { "HPE_" "INVALID_PATH", "invalid path" }, { "HPE_" "INVALID_QUERY_STRING", "invalid query string" }, { "HPE_" "INVALID_FRAGMENT", "invalid fragment" }, { "HPE_" "LF_EXPECTED", "CROW_LF character expected" }, { "HPE_" "INVALID_HEADER_TOKEN", "invalid character in header" }, { "HPE_" "INVALID_CONTENT_LENGTH", "invalid character in content-length header" }, { "HPE_" "INVALID_CHUNK_SIZE", "invalid character in chunk size header" }, { "HPE_" "INVALID_CONSTANT", "invalid constant string" }, { "HPE_" "INVALID_INTERNAL_STATE", "encountered unexpected internal state" }, { "HPE_" "STRICT", "strict mode assertion failed" }, { "HPE_" "PAUSED", "parser is paused" }, { "HPE_" "UNKNOWN", "an unknown error occurred" },
};

  assert(err < (sizeof(http_strerror_tab)/sizeof(http_strerror_tab[0])));
  return http_strerror_tab[err].name;
}

inline const char *
http_errno_description(enum http_errno err) {


static struct {
  const char *name;
  const char *description;
} http_strerror_tab[] = {
  { "HPE_" "OK", "success" }, { "HPE_" "CB_message_begin", "the on_message_begin callback failed" }, { "HPE_" "CB_url", "the on_url callback failed" }, { "HPE_" "CB_header_field", "the on_header_field callback failed" }, { "HPE_" "CB_header_value", "the on_header_value callback failed" }, { "HPE_" "CB_headers_complete", "the on_headers_complete callback failed" }, { "HPE_" "CB_body", "the on_body callback failed" }, { "HPE_" "CB_message_complete", "the on_message_complete callback failed" }, { "HPE_" "CB_status", "the on_status callback failed" }, { "HPE_" "INVALID_EOF_STATE", "stream ended at an unexpected time" }, { "HPE_" "HEADER_OVERFLOW", "too many header bytes seen; overflow detected" }, { "HPE_" "CLOSED_CONNECTION", "data received after completed connection: close message" }, { "HPE_" "INVALID_VERSION", "invalid HTTP version" }, { "HPE_" "INVALID_STATUS", "invalid HTTP status code" }, { "HPE_" "INVALID_METHOD", "invalid HTTP method" }, { "HPE_" "INVALID_URL", "invalid URL" }, { "HPE_" "INVALID_HOST", "invalid host" }, { "HPE_" "INVALID_PORT", "invalid port" }, { "HPE_" "INVALID_PATH", "invalid path" }, { "HPE_" "INVALID_QUERY_STRING", "invalid query string" }, { "HPE_" "INVALID_FRAGMENT", "invalid fragment" }, { "HPE_" "LF_EXPECTED", "CROW_LF character expected" }, { "HPE_" "INVALID_HEADER_TOKEN", "invalid character in header" }, { "HPE_" "INVALID_CONTENT_LENGTH", "invalid character in content-length header" }, { "HPE_" "INVALID_CHUNK_SIZE", "invalid character in chunk size header" }, { "HPE_" "INVALID_CONSTANT", "invalid constant string" }, { "HPE_" "INVALID_INTERNAL_STATE", "encountered unexpected internal state" }, { "HPE_" "STRICT", "strict mode assertion failed" }, { "HPE_" "PAUSED", "parser is paused" }, { "HPE_" "UNKNOWN", "an unknown error occurred" },
};

  assert(err < (sizeof(http_strerror_tab)/sizeof(http_strerror_tab[0])));
  return http_strerror_tab[err].description;
}

inline static enum http_host_state
http_parse_host_char(enum http_host_state s, const char ch) {
  switch(s) {
    case s_http_userinfo:
    case s_http_userinfo_start:
      if (ch == '@') {
        return s_http_host_start;
      }

      if (((((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z') || ((ch) >= '0' && (ch) <= '9')) || ((ch) == '-' || (ch) == '_' || (ch) == '.' || (ch) == '!' || (ch) == '~' || (ch) == '*' || (ch) == '\'' || (ch) == '(' || (ch) == ')') || (ch) == '%' || (ch) == ';' || (ch) == ':' || (ch) == '&' || (ch) == '=' || (ch) == '+' || (ch) == '$' || (ch) == ',')) {
        return s_http_userinfo;
      }
      break;

    case s_http_host_start:
      if (ch == '[') {
        return s_http_host_v6_start;
      }

      if (((((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z') || ((ch) >= '0' && (ch) <= '9')) || (ch) == '.' || (ch) == '-')) {
        return s_http_host;
      }

      break;

    case s_http_host:
      if (((((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z') || ((ch) >= '0' && (ch) <= '9')) || (ch) == '.' || (ch) == '-')) {
        return s_http_host;
      }


    case s_http_host_v6_end:
      if (ch == ':') {
        return s_http_host_port_start;
      }

      break;

    case s_http_host_v6:
      if (ch == ']') {
        return s_http_host_v6_end;
      }


    case s_http_host_v6_start:
      if ((((ch) >= '0' && (ch) <= '9') || ((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'f')) || ch == ':' || ch == '.') {
        return s_http_host_v6;
      }

      break;

    case s_http_host_port:
    case s_http_host_port_start:
      if (((ch) >= '0' && (ch) <= '9')) {
        return s_http_host_port;
      }

      break;

    default:
      break;
  }
  return s_http_host_dead;
}

inline int
http_parse_host(const char * buf, struct http_parser_url *u, int found_at) {
  enum http_host_state s;

  const char *p;
  size_t buflen = u->field_data[UF_HOST].off + u->field_data[UF_HOST].len;

  u->field_data[UF_HOST].len = 0;

  s = found_at ? s_http_userinfo_start : s_http_host_start;

  for (p = buf + u->field_data[UF_HOST].off; p < buf + buflen; p++) {
    enum http_host_state new_s = http_parse_host_char(s, *p);

    if (new_s == s_http_host_dead) {
      return 1;
    }

    switch(new_s) {
      case s_http_host:
        if (s != s_http_host) {
          u->field_data[UF_HOST].off = p - buf;
        }
        u->field_data[UF_HOST].len++;
        break;

      case s_http_host_v6:
        if (s != s_http_host_v6) {
          u->field_data[UF_HOST].off = p - buf;
        }
        u->field_data[UF_HOST].len++;
        break;

      case s_http_host_port:
        if (s != s_http_host_port) {
          u->field_data[UF_PORT].off = p - buf;
          u->field_data[UF_PORT].len = 0;
          u->field_set |= (1 << UF_PORT);
        }
        u->field_data[UF_PORT].len++;
        break;

      case s_http_userinfo:
        if (s != s_http_userinfo) {
          u->field_data[UF_USERINFO].off = p - buf ;
          u->field_data[UF_USERINFO].len = 0;
          u->field_set |= (1 << UF_USERINFO);
        }
        u->field_data[UF_USERINFO].len++;
        break;

      default:
        break;
    }
    s = new_s;
  }


  switch (s) {
    case s_http_host_start:
    case s_http_host_v6_start:
    case s_http_host_v6:
    case s_http_host_port_start:
    case s_http_userinfo:
    case s_http_userinfo_start:
      return 1;
    default:
      break;
  }

  return 0;
}

inline int
http_parser_parse_url(const char *buf, size_t buflen, int is_connect,
                      struct http_parser_url *u)
{
  enum state s;
  const char *p;
  enum http_parser_url_fields uf, old_uf;
  int found_at = 0;

  u->port = u->field_set = 0;
  s = is_connect ? s_req_server_start : s_req_spaces_before_url;
  old_uf = UF_MAX;

  for (p = buf; p < buf + buflen; p++) {
    s = parse_url_char(s, *p);


    switch (s) {
      case s_dead:
        return 1;


      case s_req_schema_slash:
      case s_req_schema_slash_slash:
      case s_req_server_start:
      case s_req_query_string_start:
      case s_req_fragment_start:
        continue;

      case s_req_schema:
        uf = UF_SCHEMA;
        break;

      case s_req_server_with_at:
        found_at = 1;


      case s_req_server:
        uf = UF_HOST;
        break;

      case s_req_path:
        uf = UF_PATH;
        break;

      case s_req_query_string:
        uf = UF_QUERY;
        break;

      case s_req_fragment:
        uf = UF_FRAGMENT;
        break;

      default:
        assert(!"Unexpected state");
        return 1;
    }


    if (uf == old_uf) {
      u->field_data[uf].len++;
      continue;
    }

    u->field_data[uf].off = p - buf;
    u->field_data[uf].len = 1;

    u->field_set |= (1 << uf);
    old_uf = uf;
  }



  if ((u->field_set & ((1 << UF_SCHEMA) | (1 << UF_HOST))) != 0) {
    if (http_parse_host(buf, u, found_at) != 0) {
      return 1;
    }
  }


  if (is_connect && u->field_set != ((1 << UF_HOST)|(1 << UF_PORT))) {
    return 1;
  }

  if (u->field_set & (1 << UF_PORT)) {

    unsigned long v = strtoul(buf + u->field_data[UF_PORT].off, NULL, 10);


    if (v > 0xffff) {
      return 1;
    }

    u->port = (uint16_t) v;
  }

  return 0;
}

inline void
http_parser_pause(http_parser *parser, int paused) {




  if (((enum http_errno) (parser)->http_errno) == HPE_OK ||
      ((enum http_errno) (parser)->http_errno) == HPE_PAUSED) {
    do { parser->http_errno = ((paused) ? HPE_PAUSED : HPE_OK); } while(0);
  } else {
    assert(0 && "Attempting to pause parser in error state");
  }
}

inline int
http_body_is_final(const struct http_parser *parser) {
    return parser->state == s_message_done;
}

inline unsigned long
http_parser_version(void) {
  return 2 * 0x10000 |
         3 * 0x00100 |
         0 * 0x00001;
}

}


       





namespace crow
{
    struct ci_hash
    {
        size_t operator()(const std::string& key) const
        {
            std::size_t seed = 0;
            std::locale locale;

            for(auto c : key)
            {
                boost::hash_combine(seed, std::toupper(c, locale));
            }

            return seed;
        }
    };

    struct ci_key_eq
    {
        bool operator()(const std::string& l, const std::string& r) const
        {
            return boost::iequals(l, r);
        }
    };

    using ci_map = std::unordered_multimap<std::string, std::string, ci_hash, ci_key_eq>;
}







namespace sha1
{
 class SHA1
 {
 public:
  typedef uint32_t digest32_t[5];
  typedef uint8_t digest8_t[20];
  inline static uint32_t LeftRotate(uint32_t value, size_t count) {
   return (value << count) ^ (value >> (32-count));
  }
  SHA1(){ reset(); }
  virtual ~SHA1() {}
  SHA1(const SHA1& s) { *this = s; }
  const SHA1& operator = (const SHA1& s) {
   memcpy(m_digest, s.m_digest, 5 * sizeof(uint32_t));
   memcpy(m_block, s.m_block, 64);
   m_blockByteIndex = s.m_blockByteIndex;
   m_byteCount = s.m_byteCount;
   return *this;
  }
  SHA1& reset() {
   m_digest[0] = 0x67452301;
   m_digest[1] = 0xEFCDAB89;
   m_digest[2] = 0x98BADCFE;
   m_digest[3] = 0x10325476;
   m_digest[4] = 0xC3D2E1F0;
   m_blockByteIndex = 0;
   m_byteCount = 0;
   return *this;
  }
  SHA1& processByte(uint8_t octet) {
   this->m_block[this->m_blockByteIndex++] = octet;
   ++this->m_byteCount;
   if(m_blockByteIndex == 64) {
    this->m_blockByteIndex = 0;
    processBlock();
   }
   return *this;
  }
  SHA1& processBlock(const void* const start, const void* const end) {
   const uint8_t* begin = static_cast<const uint8_t*>(start);
   const uint8_t* finish = static_cast<const uint8_t*>(end);
   while(begin != finish) {
    processByte(*begin);
    begin++;
   }
   return *this;
  }
  SHA1& processBytes(const void* const data, size_t len) {
   const uint8_t* block = static_cast<const uint8_t*>(data);
   processBlock(block, block + len);
   return *this;
  }
  const uint32_t* getDigest(digest32_t digest) {
   size_t bitCount = this->m_byteCount * 8;
   processByte(0x80);
   if (this->m_blockByteIndex > 56) {
    while (m_blockByteIndex != 0) {
     processByte(0);
    }
    while (m_blockByteIndex < 56) {
     processByte(0);
    }
   } else {
    while (m_blockByteIndex < 56) {
     processByte(0);
    }
   }
   processByte(0);
   processByte(0);
   processByte(0);
   processByte(0);
   processByte( static_cast<unsigned char>((bitCount>>24) & 0xFF));
   processByte( static_cast<unsigned char>((bitCount>>16) & 0xFF));
   processByte( static_cast<unsigned char>((bitCount>>8 ) & 0xFF));
   processByte( static_cast<unsigned char>((bitCount) & 0xFF));

   memcpy(digest, m_digest, 5 * sizeof(uint32_t));
   return digest;
  }
  const uint8_t* getDigestBytes(digest8_t digest) {
   digest32_t d32;
   getDigest(d32);
   size_t di = 0;
   digest[di++] = ((d32[0] >> 24) & 0xFF);
   digest[di++] = ((d32[0] >> 16) & 0xFF);
   digest[di++] = ((d32[0] >> 8) & 0xFF);
   digest[di++] = ((d32[0]) & 0xFF);

   digest[di++] = ((d32[1] >> 24) & 0xFF);
   digest[di++] = ((d32[1] >> 16) & 0xFF);
   digest[di++] = ((d32[1] >> 8) & 0xFF);
   digest[di++] = ((d32[1]) & 0xFF);

   digest[di++] = ((d32[2] >> 24) & 0xFF);
   digest[di++] = ((d32[2] >> 16) & 0xFF);
   digest[di++] = ((d32[2] >> 8) & 0xFF);
   digest[di++] = ((d32[2]) & 0xFF);

   digest[di++] = ((d32[3] >> 24) & 0xFF);
   digest[di++] = ((d32[3] >> 16) & 0xFF);
   digest[di++] = ((d32[3] >> 8) & 0xFF);
   digest[di++] = ((d32[3]) & 0xFF);

   digest[di++] = ((d32[4] >> 24) & 0xFF);
   digest[di++] = ((d32[4] >> 16) & 0xFF);
   digest[di++] = ((d32[4] >> 8) & 0xFF);
   digest[di++] = ((d32[4]) & 0xFF);
   return digest;
  }

 protected:
  void processBlock() {
   uint32_t w[80];
   for (size_t i = 0; i < 16; i++) {
    w[i] = (m_block[i*4 + 0] << 24);
    w[i] |= (m_block[i*4 + 1] << 16);
    w[i] |= (m_block[i*4 + 2] << 8);
    w[i] |= (m_block[i*4 + 3]);
   }
   for (size_t i = 16; i < 80; i++) {
    w[i] = LeftRotate((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
   }

   uint32_t a = m_digest[0];
   uint32_t b = m_digest[1];
   uint32_t c = m_digest[2];
   uint32_t d = m_digest[3];
   uint32_t e = m_digest[4];

   for (std::size_t i=0; i<80; ++i) {
    uint32_t f = 0;
    uint32_t k = 0;

    if (i<20) {
     f = (b & c) | (~b & d);
     k = 0x5A827999;
    } else if (i<40) {
     f = b ^ c ^ d;
     k = 0x6ED9EBA1;
    } else if (i<60) {
     f = (b & c) | (b & d) | (c & d);
     k = 0x8F1BBCDC;
    } else {
     f = b ^ c ^ d;
     k = 0xCA62C1D6;
    }
    uint32_t temp = LeftRotate(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = LeftRotate(b, 30);
    b = a;
    a = temp;
   }

   m_digest[0] += a;
   m_digest[1] += b;
   m_digest[2] += c;
   m_digest[3] += d;
   m_digest[4] += e;
  }
 private:
  digest32_t m_digest;
  uint8_t m_block[64];
  size_t m_blockByteIndex;
  size_t m_byteCount;
 };
}


       


       





namespace crow
{
    using namespace boost;
    using tcp = asio::ip::tcp;

    struct SocketAdaptor
    {
        using context = void;
        SocketAdaptor(boost::asio::io_service& io_service, context*)
            : socket_(io_service)
        {
        }

        boost::asio::io_service& get_io_service()
        {
            return static_cast<boost::asio::io_service&>(socket_.get_executor().context());
        }

        tcp::socket& raw_socket()
        {
            return socket_;
        }

        tcp::socket& socket()
        {
            return socket_;
        }

        tcp::endpoint remote_endpoint()
        {
            return socket_.remote_endpoint();
        }

        bool is_open()
        {
            return socket_.is_open();
        }

        void close()
        {
            boost::system::error_code ec;
            socket_.close(ec);
        }

        template <typename F>
        void start(F f)
        {
            f(boost::system::error_code());
        }

        tcp::socket socket_;
    };

}


       













namespace crow
{
    namespace mustache
    {
        class template_t;
    }

    namespace json
    {
        inline void escape(const std::string& str, std::string& ret)
        {
            ret.reserve(ret.size() + str.size()+str.size()/4);
            for(char c:str)
            {
                switch(c)
                {
                    case '"': ret += "\\\""; break;
                    case '\\': ret += "\\\\"; break;
                    case '\n': ret += "\\n"; break;
                    case '\b': ret += "\\b"; break;
                    case '\f': ret += "\\f"; break;
                    case '\r': ret += "\\r"; break;
                    case '\t': ret += "\\t"; break;
                    default:
                        if (0 <= c && c < 0x20)
                        {
                            ret += "\\u00";
                            auto to_hex = [](char c)
                            {
                                c = c&0xf;
                                if (c < 10)
                                    return '0' + c;
                                return 'a'+c-10;
                            };
                            ret += to_hex(c/16);
                            ret += to_hex(c%16);
                        }
                        else
                            ret += c;
                        break;
                }
            }
        }
        inline std::string escape(const std::string& str)
        {
            std::string ret;
            escape(str, ret);
            return ret;
        }

        enum class type : char
        {
            Null,
            False,
            True,
            Number,
            String,
            List,
            Object,
        };

        inline const char* get_type_str(type t) {
            switch(t){
                case type::Number: return "Number";
                case type::False: return "False";
                case type::True: return "True";
                case type::List: return "List";
                case type::String: return "String";
                case type::Object: return "Object";
                default: return "Unknown";
            }
        }

        enum class num_type : char {
            Signed_integer,
            Unsigned_integer,
            Floating_point,
            Null
        };

        class rvalue;
        rvalue load(const char* data, size_t size);

        namespace detail
        {

            struct r_string
                : boost::less_than_comparable<r_string>,
                boost::less_than_comparable<r_string, std::string>,
                boost::equality_comparable<r_string>,
                boost::equality_comparable<r_string, std::string>
            {
                r_string() {};
                r_string(char* s, char* e)
                    : s_(s), e_(e)
                {};
                ~r_string()
                {
                    if (owned_)
                        delete[] s_;
                }

                r_string(const r_string& r)
                {
                    *this = r;
                }

                r_string(r_string&& r)
                {
                    *this = r;
                }

                r_string& operator = (r_string&& r)
                {
                    s_ = r.s_;
                    e_ = r.e_;
                    owned_ = r.owned_;
                    if (r.owned_)
                        r.owned_ = 0;
                    return *this;
                }

                r_string& operator = (const r_string& r)
                {
                    s_ = r.s_;
                    e_ = r.e_;
                    owned_ = 0;
                    return *this;
                }

                operator std::string () const
                {
                    return std::string(s_, e_);
                }


                const char* begin() const { return s_; }
                const char* end() const { return e_; }
                size_t size() const { return end() - begin(); }

                using iterator = const char*;
                using const_iterator = const char*;

                char* s_;
                mutable char* e_;
                uint8_t owned_{0};
                friend std::ostream& operator << (std::ostream& os, const r_string& s)
                {
                    os << (std::string)s;
                    return os;
                }
            private:
                void force(char* s, uint32_t length)
                {
                    s_ = s;
                    e_ = s_ + length;
                    owned_ = 1;
                }
                friend rvalue crow::json::load(const char* data, size_t size);
            };

            inline bool operator < (const r_string& l, const r_string& r)
            {
                return boost::lexicographical_compare(l,r);
            }

            inline bool operator < (const r_string& l, const std::string& r)
            {
                return boost::lexicographical_compare(l,r);
            }

            inline bool operator > (const r_string& l, const std::string& r)
            {
                return boost::lexicographical_compare(r,l);
            }

            inline bool operator == (const r_string& l, const r_string& r)
            {
                return boost::equals(l,r);
            }

            inline bool operator == (const r_string& l, const std::string& r)
            {
                return boost::equals(l,r);
            }
        }

        class rvalue
        {
            static const int cached_bit = 2;
            static const int error_bit = 4;
        public:
            rvalue() noexcept : option_{error_bit}
            {}
            rvalue(type t) noexcept
                : lsize_{}, lremain_{}, t_{t}
            {}
            rvalue(type t, char* s, char* e) noexcept
                : start_{s},
                end_{e},
                t_{t}
            {
                determine_num_type();
            }

            rvalue(const rvalue& r)
            : start_(r.start_),
                end_(r.end_),
                key_(r.key_),
                t_(r.t_),
                nt_(r.nt_),
                option_(r.option_)
            {
                copy_l(r);
            }

            rvalue(rvalue&& r) noexcept
            {
                *this = std::move(r);
            }

            rvalue& operator = (const rvalue& r)
            {
                start_ = r.start_;
                end_ = r.end_;
                key_ = r.key_;
                t_ = r.t_;
                nt_ = r.nt_;
                option_ = r.option_;
                copy_l(r);
                return *this;
            }
            rvalue& operator = (rvalue&& r) noexcept
            {
                start_ = r.start_;
                end_ = r.end_;
                key_ = std::move(r.key_);
                l_ = std::move(r.l_);
                lsize_ = r.lsize_;
                lremain_ = r.lremain_;
                t_ = r.t_;
                nt_ = r.nt_;
                option_ = r.option_;
                return *this;
            }

            explicit operator bool() const noexcept
            {
                return (option_ & error_bit) == 0;
            }

            explicit operator int64_t() const
            {
                return i();
            }

            explicit operator uint64_t() const
            {
                return u();
            }

            explicit operator int() const
            {
                return (int)i();
            }

            type t() const
            {

                if (option_ & error_bit)
                {
                    throw std::runtime_error("invalid json object");
                }

                return t_;
            }

            num_type nt() const
            {

                if (option_ & error_bit)
                {
                    throw std::runtime_error("invalid json object");
                }

                return nt_;
            }

            int64_t i() const
            {

                switch (t()) {
                    case type::Number:
                    case type::String:
                        return boost::lexical_cast<int64_t>(start_, end_-start_);
                    default:
                        const std::string msg = "expected number, got: "
                            + std::string(get_type_str(t()));
                        throw std::runtime_error(msg);
                }

                return boost::lexical_cast<int64_t>(start_, end_-start_);
            }

            uint64_t u() const
            {

                switch (t()) {
                    case type::Number:
                    case type::String:
                        return boost::lexical_cast<uint64_t>(start_, end_-start_);
                    default:
                        throw std::runtime_error(std::string("expected number, got: ") + get_type_str(t()));
                }

                return boost::lexical_cast<uint64_t>(start_, end_-start_);
            }

            double d() const
            {

                if (t() != type::Number)
                    throw std::runtime_error("value is not number");

                return boost::lexical_cast<double>(start_, end_-start_);
            }

            bool b() const
            {

                if (t() != type::True && t() != type::False)
                    throw std::runtime_error("value is not boolean");

                return t() == type::True;
            }

            void unescape() const
            {
                if (*(start_-1))
                {
                    char* head = start_;
                    char* tail = start_;
                    while(head != end_)
                    {
                        if (*head == '\\')
                        {
                            switch(*++head)
                            {
                                case '"': *tail++ = '"'; break;
                                case '\\': *tail++ = '\\'; break;
                                case '/': *tail++ = '/'; break;
                                case 'b': *tail++ = '\b'; break;
                                case 'f': *tail++ = '\f'; break;
                                case 'n': *tail++ = '\n'; break;
                                case 'r': *tail++ = '\r'; break;
                                case 't': *tail++ = '\t'; break;
                                case 'u':
                                    {
                                        auto from_hex = [](char c)
                                        {
                                            if (c >= 'a')
                                                return c - 'a' + 10;
                                            if (c >= 'A')
                                                return c - 'A' + 10;
                                            return c - '0';
                                        };
                                        unsigned int code =
                                            (from_hex(head[1])<<12) +
                                            (from_hex(head[2])<< 8) +
                                            (from_hex(head[3])<< 4) +
                                            from_hex(head[4]);
                                        if (code >= 0x800)
                                        {
                                            *tail++ = 0xE0 | (code >> 12);
                                            *tail++ = 0x80 | ((code >> 6) & 0x3F);
                                            *tail++ = 0x80 | (code & 0x3F);
                                        }
                                        else if (code >= 0x80)
                                        {
                                            *tail++ = 0xC0 | (code >> 6);
                                            *tail++ = 0x80 | (code & 0x3F);
                                        }
                                        else
                                        {
                                            *tail++ = code;
                                        }
                                        head += 4;
                                    }
                                    break;
                            }
                        }
                        else
                            *tail++ = *head;
                        head++;
                    }
                    end_ = tail;
                    *end_ = 0;
                    *(start_-1) = 0;
                }
            }

            detail::r_string s() const
            {

                if (t() != type::String)
                    throw std::runtime_error("value is not string");

                unescape();
                return detail::r_string{start_, end_};
            }

            bool has(const char* str) const
            {
                return has(std::string(str));
            }

            bool has(const std::string& str) const
            {
                struct Pred
                {
                    bool operator()(const rvalue& l, const rvalue& r) const
                    {
                        return l.key_ < r.key_;
                    };
                    bool operator()(const rvalue& l, const std::string& r) const
                    {
                        return l.key_ < r;
                    };
                    bool operator()(const std::string& l, const rvalue& r) const
                    {
                        return l < r.key_;
                    };
                };
                if (!is_cached())
                {
                    std::sort(begin(), end(), Pred());
                    set_cached();
                }
                auto it = lower_bound(begin(), end(), str, Pred());
                return it != end() && it->key_ == str;
            }

            int count(const std::string& str)
            {
                return has(str) ? 1 : 0;
            }

            rvalue* begin() const
            {

                if (t() != type::Object && t() != type::List)
                    throw std::runtime_error("value is not a container");

                return l_.get();
            }
            rvalue* end() const
            {

                if (t() != type::Object && t() != type::List)
                    throw std::runtime_error("value is not a container");

                return l_.get()+lsize_;
            }

            const detail::r_string& key() const
            {
                return key_;
            }

            size_t size() const
            {
                if (t() == type::String)
                    return s().size();

                if (t() != type::Object && t() != type::List)
                    throw std::runtime_error("value is not a container");

                return lsize_;
            }

            const rvalue& operator[](int index) const
            {

                if (t() != type::List)
                    throw std::runtime_error("value is not a list");
                if (index >= (int)lsize_ || index < 0)
                    throw std::runtime_error("list out of bound");

                return l_[index];
            }

            const rvalue& operator[](size_t index) const
            {

                if (t() != type::List)
                    throw std::runtime_error("value is not a list");
                if (index >= lsize_)
                    throw std::runtime_error("list out of bound");

                return l_[index];
            }

            const rvalue& operator[](const char* str) const
            {
                return this->operator[](std::string(str));
            }

            const rvalue& operator[](const std::string& str) const
            {

                if (t() != type::Object)
                    throw std::runtime_error("value is not an object");

                struct Pred
                {
                    bool operator()(const rvalue& l, const rvalue& r) const
                    {
                        return l.key_ < r.key_;
                    };
                    bool operator()(const rvalue& l, const std::string& r) const
                    {
                        return l.key_ < r;
                    };
                    bool operator()(const std::string& l, const rvalue& r) const
                    {
                        return l < r.key_;
                    };
                };
                if (!is_cached())
                {
                    std::sort(begin(), end(), Pred());
                    set_cached();
                }
                auto it = lower_bound(begin(), end(), str, Pred());
                if (it != end() && it->key_ == str)
                    return *it;

                throw std::runtime_error("cannot find key");




            }

            void set_error()
            {
                option_|=error_bit;
            }

            bool error() const
            {
                return (option_&error_bit)!=0;
            }
        private:
            bool is_cached() const
            {
                return (option_&cached_bit)!=0;
            }
            void set_cached() const
            {
                option_ |= cached_bit;
            }
            void copy_l(const rvalue& r)
            {
                if (r.t() != type::Object && r.t() != type::List)
                    return;
                lsize_ = r.lsize_;
                lremain_ = 0;
                l_.reset(new rvalue[lsize_]);
                std::copy(r.begin(), r.end(), begin());
            }

            void emplace_back(rvalue&& v)
            {
                if (!lremain_)
                {
                    int new_size = lsize_ + lsize_;
                    if (new_size - lsize_ > 60000)
                        new_size = lsize_ + 60000;
                    if (new_size < 4)
                        new_size = 4;
                    rvalue* p = new rvalue[new_size];
                    rvalue* p2 = p;
                    for(auto& x : *this)
                        *p2++ = std::move(x);
                    l_.reset(p);
                    lremain_ = new_size - lsize_;
                }
                l_[lsize_++] = std::move(v);
                lremain_ --;
            }


            void determine_num_type()
            {
                if (t_ != type::Number)
                {
                    nt_ = num_type::Null;
                    return;
                }

                const std::size_t len = end_ - start_;
                const bool has_minus = std::memchr(start_, '-', len) != nullptr;
                const bool has_e = std::memchr(start_, 'e', len) != nullptr
                                || std::memchr(start_, 'E', len) != nullptr;
                const bool has_dec_sep = std::memchr(start_, '.', len) != nullptr;
                if (has_dec_sep || has_e)
                  nt_ = num_type::Floating_point;
                else if (has_minus)
                  nt_ = num_type::Signed_integer;
                else
                  nt_ = num_type::Unsigned_integer;
            }

            mutable char* start_;
            mutable char* end_;
            detail::r_string key_;
            std::unique_ptr<rvalue[]> l_;
            uint32_t lsize_;
            uint16_t lremain_;
            type t_;
            num_type nt_{num_type::Null};
            mutable uint8_t option_{0};

            friend rvalue load_nocopy_internal(char* data, size_t size);
            friend rvalue load(const char* data, size_t size);
            friend std::ostream& operator <<(std::ostream& os, const rvalue& r)
            {
                switch(r.t_)
                {

                case type::Null: os << "null"; break;
                case type::False: os << "false"; break;
                case type::True: os << "true"; break;
                case type::Number:
                    {
                        switch (r.nt())
                        {
                        case num_type::Floating_point: os << r.d(); break;
                        case num_type::Signed_integer: os << r.i(); break;
                        case num_type::Unsigned_integer: os << r.u(); break;
                        case num_type::Null: throw std::runtime_error("Number with num_type Null");
                        }
                    }
                    break;
                case type::String: os << '"' << r.s() << '"'; break;
                case type::List:
                    {
                        os << '[';
                        bool first = true;
                        for(auto& x : r)
                        {
                            if (!first)
                                os << ',';
                            first = false;
                            os << x;
                        }
                        os << ']';
                    }
                    break;
                case type::Object:
                    {
                        os << '{';
                        bool first = true;
                        for(auto& x : r)
                        {
                            if (!first)
                                os << ',';
                            os << '"' << escape(x.key_) << "\":";
                            first = false;
                            os << x;
                        }
                        os << '}';
                    }
                    break;
                }
                return os;
            }
        };
        namespace detail {
        }

        inline bool operator == (const rvalue& l, const std::string& r)
        {
            return l.s() == r;
        }

        inline bool operator == (const std::string& l, const rvalue& r)
        {
            return l == r.s();
        }

        inline bool operator != (const rvalue& l, const std::string& r)
        {
            return l.s() != r;
        }

        inline bool operator != (const std::string& l, const rvalue& r)
        {
            return l != r.s();
        }

        inline bool operator == (const rvalue& l, double r)
        {
            return l.d() == r;
        }

        inline bool operator == (double l, const rvalue& r)
        {
            return l == r.d();
        }

        inline bool operator != (const rvalue& l, double r)
        {
            return l.d() != r;
        }

        inline bool operator != (double l, const rvalue& r)
        {
            return l != r.d();
        }


        inline rvalue load_nocopy_internal(char* data, size_t size)
        {

            struct Parser
            {
                Parser(char* data, size_t )
                    : data(data)
                {
                }

                bool consume(char c)
                {
                    if (__builtin_expect(*data != c, 0))
                        return false;
                    data++;
                    return true;
                }

                void ws_skip()
                {
                    while(*data == ' ' || *data == '\t' || *data == '\r' || *data == '\n') ++data;
                };

                rvalue decode_string()
                {
                    if (__builtin_expect(!consume('"'), 0))
                        return {};
                    char* start = data;
                    uint8_t has_escaping = 0;
                    while(1)
                    {
                        if (__builtin_expect(*data != '"' && *data != '\\' && *data != '\0', 1))
                        {
                            data ++;
                        }
                        else if (*data == '"')
                        {
                            *data = 0;
                            *(start-1) = has_escaping;
                            data++;
                            return {type::String, start, data-1};
                        }
                        else if (*data == '\\')
                        {
                            has_escaping = 1;
                            data++;
                            switch(*data)
                            {
                                case 'u':
                                    {
                                        auto check = [](char c)
                                        {
                                            return
                                                ('0' <= c && c <= '9') ||
                                                ('a' <= c && c <= 'f') ||
                                                ('A' <= c && c <= 'F');
                                        };
                                        if (!(check(*(data+1)) &&
                                            check(*(data+2)) &&
                                            check(*(data+3)) &&
                                            check(*(data+4))))
                                            return {};
                                    }
                                    data += 5;
                                    break;
                                case '"':
                                case '\\':
                                case '/':
                                case 'b':
                                case 'f':
                                case 'n':
                                case 'r':
                                case 't':
                                    data ++;
                                    break;
                                default:
                                    return {};
                            }
                        }
                        else
                            return {};
                    }
                    return {};
                }

                rvalue decode_list()
                {
                    rvalue ret(type::List);
                    if (__builtin_expect(!consume('['), 0))
                    {
                        ret.set_error();
                        return ret;
                    }
                    ws_skip();
                    if (__builtin_expect(*data == ']', 0))
                    {
                        data++;
                        return ret;
                    }

                    while(1)
                    {
                        auto v = decode_value();
                        if (__builtin_expect(!v, 0))
                        {
                            ret.set_error();
                            break;
                        }
                        ws_skip();
                        ret.emplace_back(std::move(v));
                        if (*data == ']')
                        {
                            data++;
                            break;
                        }
                        if (__builtin_expect(!consume(','), 0))
                        {
                            ret.set_error();
                            break;
                        }
                        ws_skip();
                    }
                    return ret;
                }

                rvalue decode_number()
                {
                    char* start = data;

                    enum NumberParsingState
                    {
                        Minus,
                        AfterMinus,
                        ZeroFirst,
                        Digits,
                        DigitsAfterPoints,
                        E,
                        DigitsAfterE,
                        Invalid,
                    } state{Minus};
                    while(__builtin_expect(state != Invalid, 1))
                    {
                        switch(*data)
                        {
                            case '0':
                                state = (NumberParsingState)"\2\2\7\3\4\6\6"[state];

                                break;
                            case '1': case '2': case '3':
                            case '4': case '5': case '6':
                            case '7': case '8': case '9':
                                state = (NumberParsingState)"\3\3\7\3\4\6\6"[state];
                                while(*(data+1) >= '0' && *(data+1) <= '9') data++;

                                break;
                            case '.':
                                state = (NumberParsingState)"\7\7\4\4\7\7\7"[state];

                                break;
                            case '-':
                                state = (NumberParsingState)"\1\7\7\7\7\6\7"[state];

                                break;
                            case '+':
                                state = (NumberParsingState)"\7\7\7\7\7\6\7"[state];






                                break;
                            case 'e': case 'E':
                                state = (NumberParsingState)"\7\7\7\5\5\7\7"[state];







                                break;
                            default:
                                if (__builtin_expect(state == NumberParsingState::ZeroFirst || state == NumberParsingState::Digits || state == NumberParsingState::DigitsAfterPoints || state == NumberParsingState::DigitsAfterE, 1)


                                                                                  )
                                    return {type::Number, start, data};
                                else
                                    return {};
                        }
                        data++;
                    }

                    return {};
                }

                rvalue decode_value()
                {
                    switch(*data)
                    {
                        case '[':
                            return decode_list();
                        case '{':
                            return decode_object();
                        case '"':
                            return decode_string();
                        case 't':
                            if (
                                    data[1] == 'r' &&
                                    data[2] == 'u' &&
                                    data[3] == 'e')
                            {
                                data += 4;
                                return {type::True};
                            }
                            else
                                return {};
                        case 'f':
                            if (
                                    data[1] == 'a' &&
                                    data[2] == 'l' &&
                                    data[3] == 's' &&
                                    data[4] == 'e')
                            {
                                data += 5;
                                return {type::False};
                            }
                            else
                                return {};
                        case 'n':
                            if (
                                    data[1] == 'u' &&
                                    data[2] == 'l' &&
                                    data[3] == 'l')
                            {
                                data += 4;
                                return {type::Null};
                            }
                            else
                                return {};




                        default:
                            return decode_number();
                    }
                    return {};
                }

                rvalue decode_object()
                {
                    rvalue ret(type::Object);
                    if (__builtin_expect(!consume('{'), 0))
                    {
                        ret.set_error();
                        return ret;
                    }

                    ws_skip();

                    if (__builtin_expect(*data == '}', 0))
                    {
                        data++;
                        return ret;
                    }

                    while(1)
                    {
                        auto t = decode_string();
                        if (__builtin_expect(!t, 0))
                        {
                            ret.set_error();
                            break;
                        }

                        ws_skip();
                        if (__builtin_expect(!consume(':'), 0))
                        {
                            ret.set_error();
                            break;
                        }


                        auto key = t.s();

                        ws_skip();
                        auto v = decode_value();
                        if (__builtin_expect(!v, 0))
                        {
                            ret.set_error();
                            break;
                        }
                        ws_skip();

                        v.key_ = std::move(key);
                        ret.emplace_back(std::move(v));
                        if (__builtin_expect(*data == '}', 0))
                        {
                            data++;
                            break;
                        }
                        if (__builtin_expect(!consume(','), 0))
                        {
                            ret.set_error();
                            break;
                        }
                        ws_skip();
                    }
                    return ret;
                }

                rvalue parse()
                {
                    ws_skip();
                    auto ret = decode_value();
                    ws_skip();
                    if (ret && *data != '\0')
                        ret.set_error();
                    return ret;
                }

                char* data;
            };
            return Parser(data, size).parse();
        }
        inline rvalue load(const char* data, size_t size)
        {
            char* s = new char[size+1];
            memcpy(s, data, size);
            s[size] = 0;
            auto ret = load_nocopy_internal(s, size);
            if (ret)
                ret.key_.force(s, size);
            else
                delete[] s;
            return ret;
        }

        inline rvalue load(const char* data)
        {
            return load(data, strlen(data));
        }

        inline rvalue load(const std::string& str)
        {
            return load(str.data(), str.size());
        }

        class wvalue
        {
            friend class crow::mustache::template_t;
        public:
            type t() const { return t_; }
        private:
            type t_{type::Null};
            num_type nt{num_type::Null};
            union {
              double d;
              int64_t si;
              uint64_t ui {};
            } num;
            std::string s;
            std::unique_ptr<std::vector<wvalue>> l;
            std::unique_ptr<std::unordered_map<std::string, wvalue>> o;
        public:

            wvalue() {}

            wvalue(const rvalue& r)
            {
                t_ = r.t();
                switch(r.t())
                {
                    case type::Null:
                    case type::False:
                    case type::True:
                        return;
                    case type::Number:
                        nt = r.nt();
                        if (nt == num_type::Floating_point)
                          num.d = r.d();
                        else if (nt == num_type::Signed_integer)
                          num.si = r.i();
                        else
                          num.ui = r.u();
                        return;
                    case type::String:
                        s = r.s();
                        return;
                    case type::List:
                        l = std::unique_ptr<std::vector<wvalue>>(new std::vector<wvalue>{});
                        l->reserve(r.size());
                        for(auto it = r.begin(); it != r.end(); ++it)
                            l->emplace_back(*it);
                        return;
                    case type::Object:
                        o = std::unique_ptr<
                                    std::unordered_map<std::string, wvalue>
                                >(
                                new std::unordered_map<std::string, wvalue>{});
                        for(auto it = r.begin(); it != r.end(); ++it)
                            o->emplace(it->key(), *it);
                        return;
                }
            }

            wvalue(wvalue&& r)
            {
                *this = std::move(r);
            }

            wvalue& operator = (wvalue&& r)
            {
                t_ = r.t_;
                num = r.num;
                s = std::move(r.s);
                l = std::move(r.l);
                o = std::move(r.o);
                return *this;
            }

            void clear()
            {
                reset();
            }

            void reset()
            {
                t_ = type::Null;
                l.reset();
                o.reset();
            }

            wvalue& operator = (std::nullptr_t)
            {
                reset();
                return *this;
            }
            wvalue& operator = (bool value)
            {
                reset();
                if (value)
                    t_ = type::True;
                else
                    t_ = type::False;
                return *this;
            }

            wvalue& operator = (double value)
            {
                reset();
                t_ = type::Number;
                num.d = value;
                nt = num_type::Floating_point;
                return *this;
            }

            wvalue& operator = (unsigned short value)
            {
                reset();
                t_ = type::Number;
                num.ui = value;
                nt = num_type::Unsigned_integer;
                return *this;
            }

            wvalue& operator = (short value)
            {
                reset();
                t_ = type::Number;
                num.si = value;
                nt = num_type::Signed_integer;
                return *this;
            }

            wvalue& operator = (long long value)
            {
                reset();
                t_ = type::Number;
                num.si = value;
                nt = num_type::Signed_integer;
                return *this;
            }

            wvalue& operator = (long value)
            {
                reset();
                t_ = type::Number;
                num.si = value;
                nt = num_type::Signed_integer;
                return *this;
            }

            wvalue& operator = (int value)
            {
                reset();
                t_ = type::Number;
                num.si = value;
                nt = num_type::Signed_integer;
                return *this;
            }

            wvalue& operator = (unsigned long long value)
            {
                reset();
                t_ = type::Number;
                num.ui = value;
                nt = num_type::Unsigned_integer;
                return *this;
            }

            wvalue& operator = (unsigned long value)
            {
                reset();
                t_ = type::Number;
                num.ui = value;
                nt = num_type::Unsigned_integer;
                return *this;
            }

            wvalue& operator = (unsigned int value)
            {
                reset();
                t_ = type::Number;
                num.ui = value;
                nt = num_type::Unsigned_integer;
                return *this;
            }

            wvalue& operator=(const char* str)
            {
                reset();
                t_ = type::String;
                s = str;
                return *this;
            }

            wvalue& operator=(const std::string& str)
            {
                reset();
                t_ = type::String;
                s = str;
                return *this;
            }

            wvalue& operator=(std::vector<wvalue>&& v)
            {
                if (t_ != type::List)
                    reset();
                t_ = type::List;
                if (!l)
                    l = std::unique_ptr<std::vector<wvalue>>(new std::vector<wvalue>{});
                l->clear();
                l->resize(v.size());
                size_t idx = 0;
                for(auto& x:v)
                {
                    (*l)[idx++] = std::move(x);
                }
                return *this;
            }

            template <typename T>
            wvalue& operator=(const std::vector<T>& v)
            {
                if (t_ != type::List)
                    reset();
                t_ = type::List;
                if (!l)
                    l = std::unique_ptr<std::vector<wvalue>>(new std::vector<wvalue>{});
                l->clear();
                l->resize(v.size());
                size_t idx = 0;
                for(auto& x:v)
                {
                    (*l)[idx++] = x;
                }
                return *this;
            }

            wvalue& operator[](unsigned index)
            {
                if (t_ != type::List)
                    reset();
                t_ = type::List;
                if (!l)
                    l = std::unique_ptr<std::vector<wvalue>>(new std::vector<wvalue>{});
                if (l->size() < index+1)
                    l->resize(index+1);
                return (*l)[index];
            }

            int count(const std::string& str)
            {
                if (t_ != type::Object)
                    return 0;
                if (!o)
                    return 0;
                return o->count(str);
            }

            wvalue& operator[](const std::string& str)
            {
                if (t_ != type::Object)
                    reset();
                t_ = type::Object;
                if (!o)
                    o = std::unique_ptr<
                                std::unordered_map<std::string, wvalue>
                            >(
                            new std::unordered_map<std::string, wvalue>{});
                return (*o)[str];
            }

            std::vector<std::string> keys() const
            {
                if (t_ != type::Object)
                    return {};
                std::vector<std::string> result;
                for (auto& kv:*o)
                {
                    result.push_back(kv.first);
                }
                return result;
            }

            size_t estimate_length() const
            {
                switch(t_)
                {
                    case type::Null: return 4;
                    case type::False: return 5;
                    case type::True: return 4;
                    case type::Number: return 30;
                    case type::String: return 2+s.size()+s.size()/2;
                    case type::List:
                        {
                            size_t sum{};
                            if (l)
                            {
                                for(auto& x:*l)
                                {
                                    sum += 1;
                                    sum += x.estimate_length();
                                }
                            }
                            return sum+2;
                        }
                    case type::Object:
                        {
                            size_t sum{};
                            if (o)
                            {
                                for(auto& kv:*o)
                                {
                                    sum += 2;
                                    sum += 2+kv.first.size()+kv.first.size()/2;
                                    sum += kv.second.estimate_length();
                                }
                            }
                            return sum+2;
                        }
                }
                return 1;
            }

            friend void dump_internal(const wvalue& v, std::string& out);
            friend std::string dump(const wvalue& v);
        };

        inline void dump_string(const std::string& str, std::string& out)
        {
            out.push_back('"');
            escape(str, out);
            out.push_back('"');
        }
        inline void dump_internal(const wvalue& v, std::string& out)
        {
            switch(v.t_)
            {
                case type::Null: out += "null"; break;
                case type::False: out += "false"; break;
                case type::True: out += "true"; break;
                case type::Number:
                    {
                        if (v.nt == num_type::Floating_point)
                        {





                            char outbuf[128];
                            sprintf((outbuf), ("%g"), (v.num.d));
                            out += outbuf;

                        }
                        else if (v.nt == num_type::Signed_integer)
                        {
                            out += std::to_string(v.num.si);
                        }
                        else
                        {
                            out += std::to_string(v.num.ui);
                        }
                    }
                    break;
                case type::String: dump_string(v.s, out); break;
                case type::List:
                     {
                         out.push_back('[');
                         if (v.l)
                         {
                             bool first = true;
                             for(auto& x:*v.l)
                             {
                                 if (!first)
                                 {
                                     out.push_back(',');
                                 }
                                 first = false;
                                 dump_internal(x, out);
                             }
                         }
                         out.push_back(']');
                     }
                     break;
                case type::Object:
                     {
                         out.push_back('{');
                         if (v.o)
                         {
                             bool first = true;
                             for(auto& kv:*v.o)
                             {
                                 if (!first)
                                 {
                                     out.push_back(',');
                                 }
                                 first = false;
                                 dump_string(kv.first, out);
                                 out.push_back(':');
                                 dump_internal(kv.second, out);
                             }
                         }
                         out.push_back('}');
                     }
                     break;
            }
        }

        inline std::string dump(const wvalue& v)
        {
            std::string ret;
            ret.reserve(v.estimate_length());
            dump_internal(v, ret);
            return ret;
        }




    }
}


       






namespace crow
{
    namespace mustache
    {
        using context = json::wvalue;

        template_t load(const std::string& filename);

        class invalid_template_exception : public std::exception
        {
            public:
            invalid_template_exception(const std::string& msg)
                : msg("crow::mustache error: " + msg)
            {
            }
            virtual const char* what() const throw()
            {
                return msg.c_str();
            }
            std::string msg;
        };

        enum class ActionType
        {
            Ignore,
            Tag,
            UnescapeTag,
            OpenBlock,
            CloseBlock,
            ElseBlock,
            Partial,
        };

        struct Action
        {
            int start;
            int end;
            int pos;
            ActionType t;
            Action(ActionType t, int start, int end, int pos = 0)
                : start(start), end(end), pos(pos), t(t)
            {}
        };

        class template_t
        {
        public:
            template_t(std::string body)
                : body_(std::move(body))
            {

                parse();
            }

        private:
            std::string tag_name(const Action& action)
            {
                return body_.substr(action.start, action.end - action.start);
            }
            auto find_context(const std::string& name, const std::vector<context*>& stack)->std::pair<bool, context&>
            {
                if (name == ".")
                {
                    return {true, *stack.back()};
                }
                int dotPosition = name.find(".");
                if (dotPosition == (int)name.npos)
                {
                    for(auto it = stack.rbegin(); it != stack.rend(); ++it)
                    {
                        if ((*it)->t() == json::type::Object)
                        {
                            if ((*it)->count(name))
                                return {true, (**it)[name]};
                        }
                    }
                }
                else
                {
                    std::vector<int> dotPositions;
                    dotPositions.push_back(-1);
                    while(dotPosition != (int)name.npos)
                    {
                        dotPositions.push_back(dotPosition);
                        dotPosition = name.find(".", dotPosition+1);
                    }
                    dotPositions.push_back(name.size());
                    std::vector<std::string> names;
                    names.reserve(dotPositions.size()-1);
                    for(int i = 1; i < (int)dotPositions.size(); i ++)
                        names.emplace_back(name.substr(dotPositions[i-1]+1, dotPositions[i]-dotPositions[i-1]-1));

                    for(auto it = stack.rbegin(); it != stack.rend(); ++it)
                    {
                        context* view = *it;
                        bool found = true;
                        for(auto jt = names.begin(); jt != names.end(); ++jt)
                        {
                            if (view->t() == json::type::Object &&
                                view->count(*jt))
                            {
                                view = &(*view)[*jt];
                            }
                            else
                            {
                                found = false;
                                break;
                            }
                        }
                        if (found)
                            return {true, *view};
                    }

                }

                static json::wvalue empty_str;
                empty_str = "";
                return {false, empty_str};
            }

            void escape(const std::string& in, std::string& out)
            {
                out.reserve(out.size() + in.size());
                for(auto it = in.begin(); it != in.end(); ++it)
                {
                    switch(*it)
                    {
                        case '&': out += "&amp;"; break;
                        case '<': out += "&lt;"; break;
                        case '>': out += "&gt;"; break;
                        case '"': out += "&quot;"; break;
                        case '\'': out += "&#39;"; break;
                        case '/': out += "&#x2F;"; break;
                        default: out += *it; break;
                    }
                }
            }

            void render_internal(int actionBegin, int actionEnd, std::vector<context*>& stack, std::string& out, int indent)
            {
                int current = actionBegin;

                if (indent)
                    out.insert(out.size(), indent, ' ');

                while(current < actionEnd)
                {
                    auto& fragment = fragments_[current];
                    auto& action = actions_[current];
                    render_fragment(fragment, indent, out);
                    switch(action.t)
                    {
                        case ActionType::Ignore:

                            break;
                        case ActionType::Partial:
                            {
                                std::string partial_name = tag_name(action);
                                auto partial_templ = load(partial_name);
                                int partial_indent = action.pos;
                                partial_templ.render_internal(0, partial_templ.fragments_.size()-1, stack, out, partial_indent?indent+partial_indent:0);
                            }
                            break;
                        case ActionType::UnescapeTag:
                        case ActionType::Tag:
                            {
                                auto optional_ctx = find_context(tag_name(action), stack);
                                auto& ctx = optional_ctx.second;
                                switch(ctx.t())
                                {
                                    case json::type::Number:
                                        out += json::dump(ctx);
                                        break;
                                    case json::type::String:
                                        if (action.t == ActionType::Tag)
                                            escape(ctx.s, out);
                                        else
                                            out += ctx.s;
                                        break;
                                    default:
                                        throw std::runtime_error("not implemented tag type" + boost::lexical_cast<std::string>((int)ctx.t()));
                                }
                            }
                            break;
                        case ActionType::ElseBlock:
                            {
                                static context nullContext;
                                auto optional_ctx = find_context(tag_name(action), stack);
                                if (!optional_ctx.first)
                                {
                                    stack.emplace_back(&nullContext);
                                    break;
                                }

                                auto& ctx = optional_ctx.second;
                                switch(ctx.t())
                                {
                                    case json::type::List:
                                        if (ctx.l && !ctx.l->empty())
                                            current = action.pos;
                                        else
                                            stack.emplace_back(&nullContext);
                                        break;
                                    case json::type::False:
                                    case json::type::Null:
                                        stack.emplace_back(&nullContext);
                                        break;
                                    default:
                                        current = action.pos;
                                        break;
                                }
                                break;
                            }
                        case ActionType::OpenBlock:
                            {
                                auto optional_ctx = find_context(tag_name(action), stack);
                                if (!optional_ctx.first)
                                {
                                    current = action.pos;
                                    break;
                                }

                                auto& ctx = optional_ctx.second;
                                switch(ctx.t())
                                {
                                    case json::type::List:
                                        if (ctx.l)
                                            for(auto it = ctx.l->begin(); it != ctx.l->end(); ++it)
                                            {
                                                stack.push_back(&*it);
                                                render_internal(current+1, action.pos, stack, out, indent);
                                                stack.pop_back();
                                            }
                                        current = action.pos;
                                        break;
                                    case json::type::Number:
                                    case json::type::String:
                                    case json::type::Object:
                                    case json::type::True:
                                        stack.push_back(&ctx);
                                        break;
                                    case json::type::False:
                                    case json::type::Null:
                                        current = action.pos;
                                        break;
                                    default:
                                        throw std::runtime_error("{{#: not implemented context type: " + boost::lexical_cast<std::string>((int)ctx.t()));
                                        break;
                                }
                                break;
                            }
                        case ActionType::CloseBlock:
                            stack.pop_back();
                            break;
                        default:
                            throw std::runtime_error("not implemented " + boost::lexical_cast<std::string>((int)action.t));
                    }
                    current++;
                }
                auto& fragment = fragments_[actionEnd];
                render_fragment(fragment, indent, out);
            }
            void render_fragment(const std::pair<int, int> fragment, int indent, std::string& out)
            {
                if (indent)
                {
                    for(int i = fragment.first; i < fragment.second; i ++)
                    {
                        out += body_[i];
                        if (body_[i] == '\n' && i+1 != (int)body_.size())
                            out.insert(out.size(), indent, ' ');
                    }
                }
                else
                    out.insert(out.size(), body_, fragment.first, fragment.second-fragment.first);
            }
        public:
            std::string render()
            {
                context empty_ctx;
                std::vector<context*> stack;
                stack.emplace_back(&empty_ctx);

                std::string ret;
                render_internal(0, fragments_.size()-1, stack, ret, 0);
                return ret;
            }
            std::string render(context& ctx)
            {
                std::vector<context*> stack;
                stack.emplace_back(&ctx);

                std::string ret;
                render_internal(0, fragments_.size()-1, stack, ret, 0);
                return ret;
            }

        private:

            void parse()
            {
                std::string tag_open = "{{";
                std::string tag_close = "}}";

                std::vector<int> blockPositions;

                size_t current = 0;
                while(1)
                {
                    size_t idx = body_.find(tag_open, current);
                    if (idx == body_.npos)
                    {
                        fragments_.emplace_back(current, body_.size());
                        actions_.emplace_back(ActionType::Ignore, 0, 0);
                        break;
                    }
                    fragments_.emplace_back(current, idx);

                    idx += tag_open.size();
                    size_t endIdx = body_.find(tag_close, idx);
                    if (endIdx == idx)
                    {
                        throw invalid_template_exception("empty tag is not allowed");
                    }
                    if (endIdx == body_.npos)
                    {

                        throw invalid_template_exception("not matched opening tag");
                    }
                    current = endIdx + tag_close.size();
                    switch(body_[idx])
                    {
                        case '#':
                            idx++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            blockPositions.emplace_back(actions_.size());
                            actions_.emplace_back(ActionType::OpenBlock, idx, endIdx);
                            break;
                        case '/':
                            idx++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            {
                                auto& matched = actions_[blockPositions.back()];
                                if (body_.compare(idx, endIdx-idx,
                                        body_, matched.start, matched.end - matched.start) != 0)
                                {
                                    throw invalid_template_exception("not matched {{# {{/ pair: " +
                                        body_.substr(matched.start, matched.end - matched.start) + ", " +
                                        body_.substr(idx, endIdx-idx));
                                }
                                matched.pos = actions_.size();
                            }
                            actions_.emplace_back(ActionType::CloseBlock, idx, endIdx, blockPositions.back());
                            blockPositions.pop_back();
                            break;
                        case '^':
                            idx++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            blockPositions.emplace_back(actions_.size());
                            actions_.emplace_back(ActionType::ElseBlock, idx, endIdx);
                            break;
                        case '!':

                            actions_.emplace_back(ActionType::Ignore, idx+1, endIdx);
                            break;
                        case '>':
                            idx++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            actions_.emplace_back(ActionType::Partial, idx, endIdx);
                            break;
                        case '{':
                            if (tag_open != "{{" || tag_close != "}}")
                                throw invalid_template_exception("cannot use triple mustache when delimiter changed");

                            idx ++;
                            if (body_[endIdx+2] != '}')
                            {
                                throw invalid_template_exception("{{{: }}} not matched");
                            }
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            actions_.emplace_back(ActionType::UnescapeTag, idx, endIdx);
                            current++;
                            break;
                        case '&':
                            idx ++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            actions_.emplace_back(ActionType::UnescapeTag, idx, endIdx);
                            break;
                        case '=':

                            idx ++;
                            actions_.emplace_back(ActionType::Ignore, idx, endIdx);
                            endIdx --;
                            if (body_[endIdx] != '=')
                                throw invalid_template_exception("{{=: not matching = tag: "+body_.substr(idx, endIdx-idx));
                            endIdx --;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx] == ' ') endIdx--;
                            endIdx++;
                            {
                                bool succeeded = false;
                                for(size_t i = idx; i < endIdx; i++)
                                {
                                    if (body_[i] == ' ')
                                    {
                                        tag_open = body_.substr(idx, i-idx);
                                        while(body_[i] == ' ') i++;
                                        tag_close = body_.substr(i, endIdx-i);
                                        if (tag_open.empty())
                                            throw invalid_template_exception("{{=: empty open tag");
                                        if (tag_close.empty())
                                            throw invalid_template_exception("{{=: empty close tag");

                                        if (tag_close.find(" ") != tag_close.npos)
                                            throw invalid_template_exception("{{=: invalid open/close tag: "+tag_open+" " + tag_close);
                                        succeeded = true;
                                        break;
                                    }
                                }
                                if (!succeeded)
                                    throw invalid_template_exception("{{=: cannot find space between new open/close tags");
                            }
                            break;
                        default:

                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            actions_.emplace_back(ActionType::Tag, idx, endIdx);
                            break;
                    }
                }


                for(int i = actions_.size()-2; i >= 0; i --)
                {
                    if (actions_[i].t == ActionType::Tag || actions_[i].t == ActionType::UnescapeTag)
                        continue;
                    auto& fragment_before = fragments_[i];
                    auto& fragment_after = fragments_[i+1];
                    bool is_last_action = i == (int)actions_.size()-2;
                    bool all_space_before = true;
                    int j, k;
                    for(j = fragment_before.second-1;j >= fragment_before.first;j--)
                    {
                        if (body_[j] != ' ')
                        {
                            all_space_before = false;
                            break;
                        }
                    }
                    if (all_space_before && i > 0)
                        continue;
                    if (!all_space_before && body_[j] != '\n')
                        continue;
                    bool all_space_after = true;
                    for(k = fragment_after.first; k < (int)body_.size() && k < fragment_after.second; k ++)
                    {
                        if (body_[k] != ' ')
                        {
                            all_space_after = false;
                            break;
                        }
                    }
                    if (all_space_after && !is_last_action)
                        continue;
                    if (!all_space_after &&
                            !(
                                body_[k] == '\n'
                            ||
                                (body_[k] == '\r' &&
                                k + 1 < (int)body_.size() &&
                                body_[k+1] == '\n')))
                        continue;
                    if (actions_[i].t == ActionType::Partial)
                    {
                        actions_[i].pos = fragment_before.second - j - 1;
                    }
                    fragment_before.second = j+1;
                    if (!all_space_after)
                    {
                        if (body_[k] == '\n')
                            k++;
                        else
                            k += 2;
                        fragment_after.first = k;
                    }
                }
            }

            std::vector<std::pair<int,int>> fragments_;
            std::vector<Action> actions_;
            std::string body_;
        };

        inline template_t compile(const std::string& body)
        {
            return template_t(body);
        }
        namespace detail
        {
            inline std::string& get_template_base_directory_ref()
            {
                static std::string template_base_directory = "templates";
                return template_base_directory;
            }
        }

        inline std::string default_loader(const std::string& filename)
        {
            std::string path = detail::get_template_base_directory_ref();
            if (!(path.back() == '/' || path.back() == '\\'))
                path += '/';
            path += filename;
            std::ifstream inf(path);
            if (!inf)
                return {};
            return {std::istreambuf_iterator<char>(inf), std::istreambuf_iterator<char>()};
        }

        namespace detail
        {
            inline std::function<std::string (std::string)>& get_loader_ref()
            {
                static std::function<std::string (std::string)> loader = default_loader;
                return loader;
            }
        }

        inline void set_base(const std::string& path)
        {
            auto& base = detail::get_template_base_directory_ref();
            base = path;
            if (base.back() != '\\' &&
                base.back() != '/')
            {
                base += '/';
            }
        }

        inline void set_loader(std::function<std::string(std::string)> loader)
        {
            detail::get_loader_ref() = std::move(loader);
        }

        inline std::string load_text(const std::string& filename)
        {
            return detail::get_loader_ref()(filename);
        }

        inline template_t load(const std::string& filename)
        {
            return compile(detail::get_loader_ref()(filename));
        }
    }
}


       










namespace crow
{
    enum class LogLevel
    {

        DEBUG = 0,
        INFO,
        WARNING,
        ERROR,
        CRITICAL,


        Debug = 0,
        Info,
        Warning,
        Error,
        Critical,
    };

    class ILogHandler {
        public:
            virtual void log(std::string message, LogLevel level) = 0;
    };

    class CerrLogHandler : public ILogHandler {
        public:
            void log(std::string message, LogLevel ) override {
                std::cerr << message;
            }
    };

    class logger {

        private:

            static std::string timestamp()
            {
                char date[32];
                time_t t = time(0);

                tm my_tm;




                gmtime_r(&t, &my_tm);


                size_t sz = strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &my_tm);
                return std::string(date, date+sz);
            }

        public:


            logger(std::string prefix, LogLevel level) : level_(level) {

                    stringstream_ << "(" << timestamp() << ") [" << prefix << "] ";


            }
            ~logger() {

                if(level_ >= get_current_log_level()) {
                    stringstream_ << std::endl;
                    get_handler_ref()->log(stringstream_.str(), level_);
                }

            }


            template <typename T>
            logger& operator<<(T const &value) {


                if(level_ >= get_current_log_level()) {
                    stringstream_ << value;
                }

                return *this;
            }


            static void setLogLevel(LogLevel level) {
                get_log_level_ref() = level;
            }

            static void setHandler(ILogHandler* handler) {
                get_handler_ref() = handler;
            }

            static LogLevel get_current_log_level() {
                return get_log_level_ref();
            }

        private:

            static LogLevel& get_log_level_ref()
            {
                static LogLevel current_level = (LogLevel)1;
                return current_level;
            }
            static ILogHandler*& get_handler_ref()
            {
                static CerrLogHandler default_handler;
                static ILogHandler* current_handler = &default_handler;
                return current_handler;
            }


            std::ostringstream stringstream_;
            LogLevel level_;
    };
}


       









namespace crow
{
    namespace detail
    {

        class dumb_timer_queue
        {
        public:
            using key = std::pair<dumb_timer_queue*, int>;

            void cancel(key& k)
            {
                auto self = k.first;
                k.first = nullptr;
                if (!self)
                    return;

                unsigned int index = (unsigned int)(k.second - self->step_);
                if (index < self->dq_.size())
                    self->dq_[index].second = nullptr;
            }

            key add(std::function<void()> f)
            {
                dq_.emplace_back(std::chrono::steady_clock::now(), std::move(f));
                int ret = step_+dq_.size()-1;

                if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "timer add inside: " << this << ' ' << ret ;
                return {this, ret};
            }

            void process()
            {
                if (!io_service_)
                    return;

                auto now = std::chrono::steady_clock::now();
                while(!dq_.empty())
                {
                    auto& x = dq_.front();
                    if (now - x.first < std::chrono::seconds(tick))
                        break;
                    if (x.second)
                    {
                        if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "timer call: " << this << ' ' << step_;

                        x.second();
                    }
                    dq_.pop_front();
                    step_++;
                }
            }

            void set_io_service(boost::asio::io_service& io_service)
            {
                io_service_ = &io_service;
            }

            dumb_timer_queue() noexcept
            {
            }

        private:

            int tick{5};
            boost::asio::io_service* io_service_{};
            std::deque<std::pair<decltype(std::chrono::steady_clock::now()), std::function<void()>>> dq_;
            int step_{};
        };
    }
}


       











namespace crow
{
    namespace black_magic
    {

        struct OutOfRange
        {
            OutOfRange(unsigned , unsigned ) {}
        };
        constexpr unsigned requires_in_range( unsigned i, unsigned len )
        {
            return i >= len ? throw OutOfRange(i, len) : i;
        }

        class const_str
        {
            const char * const begin_;
            unsigned size_;

            public:
            template< unsigned N >
                constexpr const_str( const char(&arr)[N] ) : begin_(arr), size_(N - 1) {
                    static_assert( N >= 1, "not a string literal");
                }
            constexpr char operator[]( unsigned i ) const {
                return requires_in_range(i, size_), begin_[i];
            }

            constexpr operator const char *() const {
                return begin_;
            }

            constexpr const char* begin() const { return begin_; }
            constexpr const char* end() const { return begin_ + size_; }

            constexpr unsigned size() const {
                return size_;
            }
        };

        constexpr unsigned find_closing_tag(const_str s, unsigned p)
        {
            return s[p] == '>' ? p : find_closing_tag(s, p+1);
        }

        constexpr bool is_valid(const_str s, unsigned i = 0, int f = 0)
        {
            return
                i == s.size()
                    ? f == 0 :
                f < 0 || f >= 2
                    ? false :
                s[i] == '<'
                    ? is_valid(s, i+1, f+1) :
                s[i] == '>'
                    ? is_valid(s, i+1, f-1) :
                is_valid(s, i+1, f);
        }

        constexpr bool is_equ_p(const char* a, const char* b, unsigned n)
        {
            return
                *a == 0 && *b == 0 && n == 0
                    ? true :
                (*a == 0 || *b == 0)
                    ? false :
                n == 0
                    ? true :
                *a != *b
                    ? false :
                is_equ_p(a+1, b+1, n-1);
        }

        constexpr bool is_equ_n(const_str a, unsigned ai, const_str b, unsigned bi, unsigned n)
        {
            return
                ai + n > a.size() || bi + n > b.size()
                    ? false :
                n == 0
                    ? true :
                a[ai] != b[bi]
                    ? false :
                is_equ_n(a,ai+1,b,bi+1,n-1);
        }

        constexpr bool is_int(const_str s, unsigned i)
        {
            return is_equ_n(s, i, "<int>", 0, 5);
        }

        constexpr bool is_uint(const_str s, unsigned i)
        {
            return is_equ_n(s, i, "<uint>", 0, 6);
        }

        constexpr bool is_float(const_str s, unsigned i)
        {
            return is_equ_n(s, i, "<float>", 0, 7) ||
                is_equ_n(s, i, "<double>", 0, 8);
        }

        constexpr bool is_str(const_str s, unsigned i)
        {
            return is_equ_n(s, i, "<str>", 0, 5) ||
                is_equ_n(s, i, "<string>", 0, 8);
        }

        constexpr bool is_path(const_str s, unsigned i)
        {
            return is_equ_n(s, i, "<path>", 0, 6);
        }

        template <typename T>
        struct parameter_tag
        {
            static const int value = 0;
        };






        template <> struct parameter_tag<int> { static const int value = 1; };
        template <> struct parameter_tag<char> { static const int value = 1; };
        template <> struct parameter_tag<short> { static const int value = 1; };
        template <> struct parameter_tag<long> { static const int value = 1; };
        template <> struct parameter_tag<long long> { static const int value = 1; };
        template <> struct parameter_tag<unsigned int> { static const int value = 2; };
        template <> struct parameter_tag<unsigned char> { static const int value = 2; };
        template <> struct parameter_tag<unsigned short> { static const int value = 2; };
        template <> struct parameter_tag<unsigned long> { static const int value = 2; };
        template <> struct parameter_tag<unsigned long long> { static const int value = 2; };
        template <> struct parameter_tag<double> { static const int value = 3; };
        template <> struct parameter_tag<std::string> { static const int value = 4; };

        template <typename ... Args>
        struct compute_parameter_tag_from_args_list;

        template <>
        struct compute_parameter_tag_from_args_list<>
        {
            static const int value = 0;
        };

        template <typename Arg, typename ... Args>
        struct compute_parameter_tag_from_args_list<Arg, Args...>
        {
            static const int sub_value =
                compute_parameter_tag_from_args_list<Args...>::value;
            static const int value =
                parameter_tag<typename std::decay<Arg>::type>::value
                ? sub_value* 6 + parameter_tag<typename std::decay<Arg>::type>::value
                : sub_value;
        };

        static inline bool is_parameter_tag_compatible(uint64_t a, uint64_t b)
        {
            if (a == 0)
                return b == 0;
            if (b == 0)
                return a == 0;
            int sa = a%6;
            int sb = a%6;
            if (sa == 5) sa = 4;
            if (sb == 5) sb = 4;
            if (sa != sb)
                return false;
            return is_parameter_tag_compatible(a/6, b/6);
        }

        static inline unsigned find_closing_tag_runtime(const char* s, unsigned p)
        {
            return
                s[p] == 0
                ? throw std::runtime_error("unmatched tag <") :
                s[p] == '>'
                ? p : find_closing_tag_runtime(s, p + 1);
        }

        static inline uint64_t get_parameter_tag_runtime(const char* s, unsigned p = 0)
        {
            return
                s[p] == 0
                    ? 0 :
                s[p] == '<' ? (
                    std::strncmp(s+p, "<int>", 5) == 0
                        ? get_parameter_tag_runtime(s, find_closing_tag_runtime(s, p)) * 6 + 1 :
                    std::strncmp(s+p, "<uint>", 6) == 0
                        ? get_parameter_tag_runtime(s, find_closing_tag_runtime(s, p)) * 6 + 2 :
                    (std::strncmp(s+p, "<float>", 7) == 0 ||
                    std::strncmp(s+p, "<double>", 8) == 0)
                        ? get_parameter_tag_runtime(s, find_closing_tag_runtime(s, p)) * 6 + 3 :
                    (std::strncmp(s+p, "<str>", 5) == 0 ||
                    std::strncmp(s+p, "<string>", 8) == 0)
                        ? get_parameter_tag_runtime(s, find_closing_tag_runtime(s, p)) * 6 + 4 :
                    std::strncmp(s+p, "<path>", 6) == 0
                        ? get_parameter_tag_runtime(s, find_closing_tag_runtime(s, p)) * 6 + 5 :
                    throw std::runtime_error("invalid parameter type")
                    ) :
                get_parameter_tag_runtime(s, p+1);
        }

        constexpr uint64_t get_parameter_tag(const_str s, unsigned p = 0)
        {
            return
                p == s.size()
                    ? 0 :
                s[p] == '<' ? (
                    is_int(s, p)
                        ? get_parameter_tag(s, find_closing_tag(s, p)) * 6 + 1 :
                    is_uint(s, p)
                        ? get_parameter_tag(s, find_closing_tag(s, p)) * 6 + 2 :
                    is_float(s, p)
                        ? get_parameter_tag(s, find_closing_tag(s, p)) * 6 + 3 :
                    is_str(s, p)
                        ? get_parameter_tag(s, find_closing_tag(s, p)) * 6 + 4 :
                    is_path(s, p)
                        ? get_parameter_tag(s, find_closing_tag(s, p)) * 6 + 5 :
                    throw std::runtime_error("invalid parameter type")
                    ) :
                get_parameter_tag(s, p+1);
        }


        template <typename ... T>
        struct S
        {
            template <typename U>
            using push = S<U, T...>;
            template <typename U>
            using push_back = S<T..., U>;
            template <template<typename ... Args> class U>
            using rebind = U<T...>;
        };
template <typename F, typename Set>
        struct CallHelper;
        template <typename F, typename ...Args>
        struct CallHelper<F, S<Args...>>
        {
            template <typename F1, typename ...Args1, typename =
                decltype(std::declval<F1>()(std::declval<Args1>()...))
                >
            static char __test(int);

            template <typename ...>
            static int __test(...);

            static constexpr bool value = sizeof(__test<F, Args...>(0)) == sizeof(char);
        };


        template <int N>
        struct single_tag_to_type
        {
        };

        template <>
        struct single_tag_to_type<1>
        {
            using type = int64_t;
        };

        template <>
        struct single_tag_to_type<2>
        {
            using type = uint64_t;
        };

        template <>
        struct single_tag_to_type<3>
        {
            using type = double;
        };

        template <>
        struct single_tag_to_type<4>
        {
            using type = std::string;
        };

        template <>
        struct single_tag_to_type<5>
        {
            using type = std::string;
        };


        template <uint64_t Tag>
        struct arguments
        {
            using subarguments = typename arguments<Tag/6>::type;
            using type =
                typename subarguments::template push<typename single_tag_to_type<Tag%6>::type>;
        };

        template <>
        struct arguments<0>
        {
            using type = S<>;
        };

        template <typename ... T>
        struct last_element_type
        {
            using type = typename std::tuple_element<sizeof...(T)-1, std::tuple<T...>>::type;
        };


        template <>
        struct last_element_type<>
        {
        };



        template<class T> using Invoke = typename T::type;

        template<unsigned...> struct seq{ using type = seq; };

        template<class S1, class S2> struct concat;

        template<unsigned... I1, unsigned... I2>
        struct concat<seq<I1...>, seq<I2...>>
          : seq<I1..., (sizeof...(I1)+I2)...>{};

        template<class S1, class S2>
        using Concat = Invoke<concat<S1, S2>>;

        template<unsigned N> struct gen_seq;
        template<unsigned N> using GenSeq = Invoke<gen_seq<N>>;

        template<unsigned N>
        struct gen_seq : Concat<GenSeq<N/2>, GenSeq<N - N/2>>{};

        template<> struct gen_seq<0> : seq<>{};
        template<> struct gen_seq<1> : seq<0>{};

        template <typename Seq, typename Tuple>
        struct pop_back_helper;

        template <unsigned ... N, typename Tuple>
        struct pop_back_helper<seq<N...>, Tuple>
        {
            template <template <typename ... Args> class U>
            using rebind = U<typename std::tuple_element<N, Tuple>::type...>;
        };

        template <typename ... T>
        struct pop_back
        {
            template <template <typename ... Args> class U>
            using rebind = typename pop_back_helper<typename gen_seq<sizeof...(T)-1>::type, std::tuple<T...>>::template rebind<U>;
        };

        template <>
        struct pop_back<>
        {
            template <template <typename ... Args> class U>
            using rebind = U<>;
        };


        template < typename Tp, typename... List >
        struct contains : std::true_type {};

        template < typename Tp, typename Head, typename... Rest >
        struct contains<Tp, Head, Rest...>
        : std::conditional< std::is_same<Tp, Head>::value,
            std::true_type,
            contains<Tp, Rest...>
        >::type {};

        template < typename Tp >
        struct contains<Tp> : std::false_type {};

        template <typename T>
        struct empty_context
        {
        };

        template <typename T>
        struct promote
        {
            using type = T;
        };

        template<> struct promote<char> { using type = int64_t; };
        template<> struct promote<short> { using type = int64_t; };
        template<> struct promote<int> { using type = int64_t; };
        template<> struct promote<long> { using type = int64_t; };
        template<> struct promote<long long> { using type = int64_t; };
        template<> struct promote<unsigned char> { using type = uint64_t; };
        template<> struct promote<unsigned short> { using type = uint64_t; };
        template<> struct promote<unsigned int> { using type = uint64_t; };
        template<> struct promote<unsigned long> { using type = uint64_t; };
        template<> struct promote<unsigned long long> { using type = uint64_t; };
        template<> struct promote<float> { using type = double; };


        template <typename T>
        using promote_t = typename promote<T>::type;

    }

    namespace detail
    {

        template <class T, std::size_t N, class... Args>
        struct get_index_of_element_from_tuple_by_type_impl
        {
            static constexpr auto value = N;
        };

        template <class T, std::size_t N, class... Args>
        struct get_index_of_element_from_tuple_by_type_impl<T, N, T, Args...>
        {
            static constexpr auto value = N;
        };

        template <class T, std::size_t N, class U, class... Args>
        struct get_index_of_element_from_tuple_by_type_impl<T, N, U, Args...>
        {
            static constexpr auto value = get_index_of_element_from_tuple_by_type_impl<T, N + 1, Args...>::value;
        };

    }

    namespace utility
    {
        template <class T, class... Args>
        T& get_element_by_type(std::tuple<Args...>& t)
        {
            return std::get<detail::get_index_of_element_from_tuple_by_type_impl<T, 0, Args...>::value>(t);
        }

        template<typename T>
        struct function_traits;


        template<typename T>
        struct function_traits : public function_traits<decltype(&T::operator())>
        {
            using parent_t = function_traits<decltype(&T::operator())>;
            static const size_t arity = parent_t::arity;
            using result_type = typename parent_t::result_type;
            template <size_t i>
            using arg = typename parent_t::template arg<i>;

        };


        template<typename ClassType, typename R, typename ...Args>
        struct function_traits<R(ClassType::*)(Args...) const>
        {
            static const size_t arity = sizeof...(Args);

            typedef R result_type;

            template <size_t i>
            using arg = typename std::tuple_element<i, std::tuple<Args...>>::type;
        };

        template<typename ClassType, typename R, typename ...Args>
        struct function_traits<R(ClassType::*)(Args...)>
        {
            static const size_t arity = sizeof...(Args);

            typedef R result_type;

            template <size_t i>
            using arg = typename std::tuple_element<i, std::tuple<Args...>>::type;
        };

        template<typename R, typename ...Args>
        struct function_traits<std::function<R(Args...)>>
        {
            static const size_t arity = sizeof...(Args);

            typedef R result_type;

            template <size_t i>
            using arg = typename std::tuple_element<i, std::tuple<Args...>>::type;
        };

        inline static std::string base64encode(const char* data, size_t size, const char* key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        {
            std::string ret;
            ret.resize((size+2) / 3 * 4);
            auto it = ret.begin();
            while(size >= 3)
            {
                *it++ = key[(((unsigned char)*data)&0xFC)>>2];
                unsigned char h = (((unsigned char)*data++) & 0x03) << 4;
                *it++ = key[h|((((unsigned char)*data)&0xF0)>>4)];
                h = (((unsigned char)*data++) & 0x0F) << 2;
                *it++ = key[h|((((unsigned char)*data)&0xC0)>>6)];
                *it++ = key[((unsigned char)*data++)&0x3F];

                size -= 3;
            }
            if (size == 1)
            {
                *it++ = key[(((unsigned char)*data)&0xFC)>>2];
                unsigned char h = (((unsigned char)*data++) & 0x03) << 4;
                *it++ = key[h];
                *it++ = '=';
                *it++ = '=';
            }
            else if (size == 2)
            {
                *it++ = key[(((unsigned char)*data)&0xFC)>>2];
                unsigned char h = (((unsigned char)*data++) & 0x03) << 4;
                *it++ = key[h|((((unsigned char)*data)&0xF0)>>4)];
                h = (((unsigned char)*data++) & 0x0F) << 2;
                *it++ = key[h];
                *it++ = '=';
            }
            return ret;
        }

        inline static std::string base64encode_urlsafe(const char* data, size_t size)
        {
            return base64encode(data, size, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
        }


    }
}


       







namespace crow
{
    enum class HTTPMethod
    {

        DELETE = 0,
        GET,
        HEAD,
        POST,
        PUT,
        CONNECT,
        OPTIONS,
        TRACE,
        PATCH,
        PURGE,


        Delete = 0,
        Get,
        Head,
        Post,
        Put,
        Connect,
        Options,
        Trace,
        Patch,
        Purge,


        InternalMethodCount,

    };

    inline std::string method_name(HTTPMethod method)
    {
        switch(method)
        {
            case HTTPMethod::Delete:
                return "DELETE";
            case HTTPMethod::Get:
                return "GET";
            case HTTPMethod::Head:
                return "HEAD";
            case HTTPMethod::Post:
                return "POST";
            case HTTPMethod::Put:
                return "PUT";
            case HTTPMethod::Connect:
                return "CONNECT";
            case HTTPMethod::Options:
                return "OPTIONS";
            case HTTPMethod::Trace:
                return "TRACE";
            case HTTPMethod::Patch:
                return "PATCH";
            case HTTPMethod::Purge:
                return "PURGE";
            default:
                return "invalid";
        }
        return "invalid";
    }

    enum class ParamType
    {
        INT,
        UINT,
        DOUBLE,
        STRING,
        PATH,

        MAX
    };

    struct routing_params
    {
        std::vector<int64_t> int_params;
        std::vector<uint64_t> uint_params;
        std::vector<double> double_params;
        std::vector<std::string> string_params;

        void debug_print() const
        {
            std::cerr << "routing_params" << std::endl;
            for(auto i:int_params)
                std::cerr<<i <<", " ;
            std::cerr<<std::endl;
            for(auto i:uint_params)
                std::cerr<<i <<", " ;
            std::cerr<<std::endl;
            for(auto i:double_params)
                std::cerr<<i <<", " ;
            std::cerr<<std::endl;
            for(auto& i:string_params)
                std::cerr<<i <<", " ;
            std::cerr<<std::endl;
        }

        template <typename T>
        T get(unsigned) const;

    };

    template<>
    inline int64_t routing_params::get<int64_t>(unsigned index) const
    {
        return int_params[index];
    }

    template<>
    inline uint64_t routing_params::get<uint64_t>(unsigned index) const
    {
        return uint_params[index];
    }

    template<>
    inline double routing_params::get<double>(unsigned index) const
    {
        return double_params[index];
    }

    template<>
    inline std::string routing_params::get<std::string>(unsigned index) const
    {
        return string_params[index];
    }
}


constexpr crow::HTTPMethod operator "" _method(const char* str, size_t )
{
    return
        crow::black_magic::is_equ_p(str, "GET", 3) ? crow::HTTPMethod::Get :
        crow::black_magic::is_equ_p(str, "DELETE", 6) ? crow::HTTPMethod::Delete :
        crow::black_magic::is_equ_p(str, "HEAD", 4) ? crow::HTTPMethod::Head :
        crow::black_magic::is_equ_p(str, "POST", 4) ? crow::HTTPMethod::Post :
        crow::black_magic::is_equ_p(str, "PUT", 3) ? crow::HTTPMethod::Put :
        crow::black_magic::is_equ_p(str, "OPTIONS", 7) ? crow::HTTPMethod::Options :
        crow::black_magic::is_equ_p(str, "CONNECT", 7) ? crow::HTTPMethod::Connect :
        crow::black_magic::is_equ_p(str, "TRACE", 5) ? crow::HTTPMethod::Trace :
        crow::black_magic::is_equ_p(str, "PATCH", 5) ? crow::HTTPMethod::Patch :
        crow::black_magic::is_equ_p(str, "PURGE", 5) ? crow::HTTPMethod::Purge :
        throw std::runtime_error("invalid http method");
}


       







namespace crow
{
    template <typename T>
    inline const std::string& get_header_value(const T& headers, const std::string& key)
    {
        if (headers.count(key))
        {
            return headers.find(key)->second;
        }
        static std::string empty;
        return empty;
    }

 struct DetachHelper;

    struct request
    {
        HTTPMethod method;
        std::string raw_url;
        std::string url;
        query_string url_params;
        ci_map headers;
        std::string body;

        void* middleware_context{};
        boost::asio::io_service* io_service{};

        request()
            : method(HTTPMethod::Get)
        {
        }

        request(HTTPMethod method, std::string raw_url, std::string url, query_string url_params, ci_map headers, std::string body)
            : method(method), raw_url(std::move(raw_url)), url(std::move(url)), url_params(std::move(url_params)), headers(std::move(headers)), body(std::move(body))
        {
        }

        void add_header(std::string key, std::string value)
        {
            headers.emplace(std::move(key), std::move(value));
        }

        const std::string& get_header_value(const std::string& key) const
        {
            return crow::get_header_value(headers, key);
        }

        template<typename CompletionHandler>
        void post(CompletionHandler handler)
        {
            io_service->post(handler);
        }

        template<typename CompletionHandler>
        void dispatch(CompletionHandler handler)
        {
            io_service->dispatch(handler);
        }

    };
}


       







namespace crow
{
    namespace websocket
    {
        enum class WebSocketReadState
        {
            MiniHeader,
            Len16,
            Len64,
            Mask,
            Payload,
        };

  struct connection
  {
            virtual void send_binary(const std::string& msg) = 0;
            virtual void send_text(const std::string& msg) = 0;
            virtual void close(const std::string& msg = "quit") = 0;
            virtual ~connection(){}

            void userdata(void* u) { userdata_ = u; }
            void* userdata() { return userdata_; }

        private:
            void* userdata_;
  };

  template <typename Adaptor>
        class Connection : public connection
        {
   public:
    Connection(const crow::request& req, Adaptor&& adaptor,
      std::function<void(crow::websocket::connection&)> open_handler,
      std::function<void(crow::websocket::connection&, const std::string&, bool)> message_handler,
      std::function<void(crow::websocket::connection&, const std::string&)> close_handler,
      std::function<void(crow::websocket::connection&)> error_handler,
      std::function<bool(const crow::request&)> accept_handler)
     : adaptor_(std::move(adaptor)), open_handler_(std::move(open_handler)), message_handler_(std::move(message_handler)), close_handler_(std::move(close_handler)), error_handler_(std::move(error_handler))
     , accept_handler_(std::move(accept_handler))
    {
     if (!boost::iequals(req.get_header_value("upgrade"), "websocket"))
     {
      adaptor.close();
      delete this;
      return;
     }

     if (accept_handler_)
     {
      if (!accept_handler_(req))
      {
       adaptor.close();
       delete this;
       return;
      }
     }



                    std::string magic = req.get_header_value("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                    sha1::SHA1 s;
                    s.processBytes(magic.data(), magic.size());
                    uint8_t digest[20];
                    s.getDigestBytes(digest);
                    start(crow::utility::base64encode((char*)digest, 20));
    }

                template<typename CompletionHandler>
                void dispatch(CompletionHandler handler)
                {
                    adaptor_.get_io_service().dispatch(handler);
                }

                template<typename CompletionHandler>
                void post(CompletionHandler handler)
                {
                    adaptor_.get_io_service().post(handler);
                }

                void send_pong(const std::string& msg)
                {
                    dispatch([this, msg]{
                        char buf[3] = "\x8A\x00";
                        buf[1] += msg.size();
                        write_buffers_.emplace_back(buf, buf+2);
                        write_buffers_.emplace_back(msg);
                        do_write();
                    });
                }

                void send_binary(const std::string& msg) override
                {
                    dispatch([this, msg]{
                        auto header = build_header(2, msg.size());
                        write_buffers_.emplace_back(std::move(header));
                        write_buffers_.emplace_back(msg);
                        do_write();
                    });
                }

                void send_text(const std::string& msg) override
                {
                    dispatch([this, msg]{
                        auto header = build_header(1, msg.size());
                        write_buffers_.emplace_back(std::move(header));
                        write_buffers_.emplace_back(msg);
                        do_write();
                    });
                }

                void close(const std::string& msg) override
                {
                    dispatch([this, msg]{
                        has_sent_close_ = true;
                        if (has_recv_close_ && !is_close_handler_called_)
                        {
                            is_close_handler_called_ = true;
                            if (close_handler_)
                                close_handler_(*this, msg);
                        }
                        auto header = build_header(0x8, msg.size());
                        write_buffers_.emplace_back(std::move(header));
                        write_buffers_.emplace_back(msg);
                        do_write();
                    });
                }

            protected:

                std::string build_header(int opcode, size_t size)
                {
                    char buf[2+8] = "\x80\x00";
                    buf[0] += opcode;
                    if (size < 126)
                    {
                        buf[1] += size;
                        return {buf, buf+2};
                    }
                    else if (size < 0x10000)
                    {
                        buf[1] += 126;
                        *(uint16_t*)(buf+2) = htons((uint16_t)size);
                        return {buf, buf+4};
                    }
                    else
                    {
                        buf[1] += 127;
                        *reinterpret_cast<uint64_t*>(buf+2) = ((1==htonl(1)) ? static_cast<uint64_t>(size) : (static_cast<uint64_t>(htonl((size) & 0xFFFFFFFF)) << 32) | htonl(static_cast<uint64_t>(size) >> 32));
                        return {buf, buf+10};
                    }
                }

                void start(std::string&& hello)
                {
                    static std::string header = "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: ";
                    static std::string crlf = "\r\n";
                    write_buffers_.emplace_back(header);
                    write_buffers_.emplace_back(std::move(hello));
                    write_buffers_.emplace_back(crlf);
                    write_buffers_.emplace_back(crlf);
                    do_write();
                    if (open_handler_)
                        open_handler_(*this);
                    do_read();
                }

                void do_read()
                {
                    is_reading = true;
                    switch(state_)
                    {
                        case WebSocketReadState::MiniHeader:
                            {

                                adaptor_.socket().async_read_some(boost::asio::buffer(&mini_header_, 2),
                                    [this](const boost::system::error_code& ec, std::size_t



                                        )

                                    {
                                        is_reading = false;
                                        mini_header_ = ntohs(mini_header_);

                                        if (!ec && ((mini_header_ & 0x80) == 0x80))
                                        {
                                            if ((mini_header_ & 0x7f) == 127)
                                            {
                                                state_ = WebSocketReadState::Len64;
                                            }
                                            else if ((mini_header_ & 0x7f) == 126)
                                            {
                                                state_ = WebSocketReadState::Len16;
                                            }
                                            else
                                            {
                                                remaining_length_ = mini_header_ & 0x7f;
                                                state_ = WebSocketReadState::Mask;
                                            }
                                            do_read();
                                        }
                                        else
                                        {
                                            close_connection_ = true;
                                            adaptor_.close();
                                            if (error_handler_)
                                                error_handler_(*this);
                                            check_destroy();
                                        }
                                    });
                            }
                            break;
                        case WebSocketReadState::Len16:
                            {
                                remaining_length_ = 0;
                                remaining_length16_ = 0;
                                boost::asio::async_read(adaptor_.socket(), boost::asio::buffer(&remaining_length16_, 2),
                                    [this](const boost::system::error_code& ec, std::size_t



                                        )
                                    {
                                        is_reading = false;
                                        remaining_length16_ = ntohs(remaining_length16_);
                                        remaining_length_ = remaining_length16_;







                                        if (!ec)
                                        {
                                            state_ = WebSocketReadState::Mask;
                                            do_read();
                                        }
                                        else
                                        {
                                            close_connection_ = true;
                                            adaptor_.close();
                                            if (error_handler_)
                                                error_handler_(*this);
                                            check_destroy();
                                        }
                                    });
                            }
                            break;
                        case WebSocketReadState::Len64:
                            {
                                boost::asio::async_read(adaptor_.socket(), boost::asio::buffer(&remaining_length_, 8),
                                    [this](const boost::system::error_code& ec, std::size_t



                                        )
                                    {
                                        is_reading = false;
                                        remaining_length_ = ((1==ntohl(1)) ? (remaining_length_) : ((uint64_t)ntohl((remaining_length_) & 0xFFFFFFFF) << 32) | ntohl((remaining_length_) >> 32));







                                        if (!ec)
                                        {
                                            state_ = WebSocketReadState::Mask;
                                            do_read();
                                        }
                                        else
                                        {
                                            close_connection_ = true;
                                            adaptor_.close();
                                            if (error_handler_)
                                                error_handler_(*this);
                                            check_destroy();
                                        }
                                    });
                            }
                            break;
                        case WebSocketReadState::Mask:
                                boost::asio::async_read(adaptor_.socket(), boost::asio::buffer((char*)&mask_, 4),
                                    [this](const boost::system::error_code& ec, std::size_t



                                    )
                                    {
                                        is_reading = false;







                                        if (!ec)
                                        {
                                            state_ = WebSocketReadState::Payload;
                                            do_read();
                                        }
                                        else
                                        {
                                            close_connection_ = true;
                                            if (error_handler_)
                                                error_handler_(*this);
                                            adaptor_.close();
                                        }
                                    });
                            break;
                        case WebSocketReadState::Payload:
                            {
                                size_t to_read = buffer_.size();
                                if (remaining_length_ < to_read)
                                    to_read = remaining_length_;
                                adaptor_.socket().async_read_some( boost::asio::buffer(buffer_, to_read),
                                    [this](const boost::system::error_code& ec, std::size_t bytes_transferred)
                                    {
                                        is_reading = false;

                                        if (!ec)
                                        {
                                            fragment_.insert(fragment_.end(), buffer_.begin(), buffer_.begin() + bytes_transferred);
                                            remaining_length_ -= bytes_transferred;
                                            if (remaining_length_ == 0)
                                            {
                                                handle_fragment();
                                                state_ = WebSocketReadState::MiniHeader;
                                                do_read();
                                            }
                                        }
                                        else
                                        {
                                            close_connection_ = true;
                                            if (error_handler_)
                                                error_handler_(*this);
                                            adaptor_.close();
                                        }
                                    });
                            }
                            break;
                    }
                }

                bool is_FIN()
                {
                    return mini_header_ & 0x8000;
                }

                int opcode()
                {
                    return (mini_header_ & 0x0f00) >> 8;
                }

                void handle_fragment()
                {
                    for(decltype(fragment_.length()) i = 0; i < fragment_.length(); i ++)
                    {
                        fragment_[i] ^= ((char*)&mask_)[i%4];
                    }
                    switch(opcode())
                    {
                        case 0:
                            {
                                message_ += fragment_;
                                if (is_FIN())
                                {
                                    if (message_handler_)
                                        message_handler_(*this, message_, is_binary_);
                                    message_.clear();
                                }
                            }
                        case 1:
                            {
                                is_binary_ = false;
                                message_ += fragment_;
                                if (is_FIN())
                                {
                                    if (message_handler_)
                                        message_handler_(*this, message_, is_binary_);
                                    message_.clear();
                                }
                            }
                            break;
                        case 2:
                            {
                                is_binary_ = true;
                                message_ += fragment_;
                                if (is_FIN())
                                {
                                    if (message_handler_)
                                        message_handler_(*this, message_, is_binary_);
                                    message_.clear();
                                }
                            }
                            break;
                        case 0x8:
                            {
                                has_recv_close_ = true;
                                if (!has_sent_close_)
                                {
                                    close(fragment_);
                                }
                                else
                                {
                                    adaptor_.close();
                                    close_connection_ = true;
                                    if (!is_close_handler_called_)
                                    {
                                        if (close_handler_)
                                            close_handler_(*this, fragment_);
                                        is_close_handler_called_ = true;
                                    }
                                    check_destroy();
                                }
                            }
                            break;
                        case 0x9:
                            {
                                send_pong(fragment_);
                            }
                            break;
                        case 0xA:
                            {
                                pong_received_ = true;
                            }
                            break;
                    }

                    fragment_.clear();
                }

                void do_write()
                {
                    if (sending_buffers_.empty())
                    {
                        sending_buffers_.swap(write_buffers_);
                        std::vector<boost::asio::const_buffer> buffers;
                        buffers.reserve(sending_buffers_.size());
                        for(auto& s:sending_buffers_)
                        {
                            buffers.emplace_back(boost::asio::buffer(s));
                        }
                        boost::asio::async_write(adaptor_.socket(), buffers,
                            [&](const boost::system::error_code& ec, std::size_t )
                            {
                                sending_buffers_.clear();
                                if (!ec && !close_connection_)
                                {
                                    if (!write_buffers_.empty())
                                        do_write();
                                    if (has_sent_close_)
                                        close_connection_ = true;
                                }
                                else
                                {
                                    close_connection_ = true;
                                    check_destroy();
                                }
                            });
                    }
                }

                void check_destroy()
                {

                    if (!is_close_handler_called_)
                        if (close_handler_)
                            close_handler_(*this, "uncleanly");
                    if (sending_buffers_.empty() && !is_reading)
                        delete this;
                }
   private:
    Adaptor adaptor_;

                std::vector<std::string> sending_buffers_;
                std::vector<std::string> write_buffers_;

                boost::array<char, 4096> buffer_;
                bool is_binary_;
                std::string message_;
                std::string fragment_;
                WebSocketReadState state_{WebSocketReadState::MiniHeader};
                uint16_t remaining_length16_{0};
                uint64_t remaining_length_{0};
                bool close_connection_{false};
                bool is_reading{false};
                uint32_t mask_;
                uint16_t mini_header_;
                bool has_sent_close_{false};
                bool has_recv_close_{false};
                bool error_occured_{false};
                bool pong_received_{false};
                bool is_close_handler_called_{false};

    std::function<void(crow::websocket::connection&)> open_handler_;
    std::function<void(crow::websocket::connection&, const std::string&, bool)> message_handler_;
    std::function<void(crow::websocket::connection&, const std::string&)> close_handler_;
    std::function<void(crow::websocket::connection&)> error_handler_;
    std::function<bool(const crow::request&)> accept_handler_;
        };
    }
}


       










namespace crow
{
    template <typename Handler>
    struct HTTPParser : public http_parser
    {
        static int on_message_begin(http_parser* self_)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);
            self->clear();
            return 0;
        }
        static int on_url(http_parser* self_, const char* at, size_t length)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);
            self->raw_url.insert(self->raw_url.end(), at, at+length);
            return 0;
        }
        static int on_header_field(http_parser* self_, const char* at, size_t length)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);
            switch (self->header_building_state)
            {
                case 0:
                    if (!self->header_value.empty())
                    {
                        self->headers.emplace(std::move(self->header_field), std::move(self->header_value));
                    }
                    self->header_field.assign(at, at+length);
                    self->header_building_state = 1;
                    break;
                case 1:
                    self->header_field.insert(self->header_field.end(), at, at+length);
                    break;
            }
            return 0;
        }
        static int on_header_value(http_parser* self_, const char* at, size_t length)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);
            switch (self->header_building_state)
            {
                case 0:
                    self->header_value.insert(self->header_value.end(), at, at+length);
                    break;
                case 1:
                    self->header_building_state = 0;
                    self->header_value.assign(at, at+length);
                    break;
            }
            return 0;
        }
        static int on_headers_complete(http_parser* self_)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);
            if (!self->header_field.empty())
            {
                self->headers.emplace(std::move(self->header_field), std::move(self->header_value));
            }
            self->process_header();
            return 0;
        }
        static int on_body(http_parser* self_, const char* at, size_t length)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);
            self->body.insert(self->body.end(), at, at+length);
            return 0;
        }
        static int on_message_complete(http_parser* self_)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);


            self->url = self->raw_url.substr(0, self->raw_url.find("?"));
            self->url_params = query_string(self->raw_url);

            self->process_message();
            return 0;
        }
        HTTPParser(Handler* handler) :
            handler_(handler)
        {
            http_parser_init(this, HTTP_REQUEST);
        }


        bool feed(const char* buffer, int length)
        {
            const static http_parser_settings settings_{
                on_message_begin,
                on_url,
                nullptr,
                on_header_field,
                on_header_value,
                on_headers_complete,
                on_body,
                on_message_complete,
            };

            int nparsed = http_parser_execute(this, &settings_, buffer, length);
            return nparsed == length;
        }

        bool done()
        {
            return feed(nullptr, 0);
        }

        void clear()
        {
            url.clear();
            raw_url.clear();
            header_building_state = 0;
            header_field.clear();
            header_value.clear();
            headers.clear();
            url_params.clear();
            body.clear();
        }

        void process_header()
        {
            handler_->handle_header();
        }

        void process_message()
        {
            handler_->handle();
        }

        request to_request() const
        {
            return request{(HTTPMethod)method, std::move(raw_url), std::move(url), std::move(url_params), std::move(headers), std::move(body)};
        }

  bool is_upgrade() const
  {
   return upgrade;
  }

        bool check_version(int major, int minor) const
        {
            return http_major == major && http_minor == minor;
        }

        std::string raw_url;
        std::string url;

        int header_building_state = 0;
        std::string header_field;
        std::string header_value;
        ci_map headers;
        query_string url_params;
        std::string body;

        Handler* handler_;
    };
}


       







namespace crow
{
    template <typename Adaptor, typename Handler, typename ... Middlewares>
    class Connection;
    struct response
    {
        template <typename Adaptor, typename Handler, typename ... Middlewares>
        friend class crow::Connection;

        int code{200};
        std::string body;
        json::wvalue json_value;


        ci_map headers;

        void set_header(std::string key, std::string value)
        {
            headers.erase(key);
            headers.emplace(std::move(key), std::move(value));
        }
        void add_header(std::string key, std::string value)
        {
            headers.emplace(std::move(key), std::move(value));
        }

        const std::string& get_header_value(const std::string& key)
        {
            return crow::get_header_value(headers, key);
        }


        response() {}
        explicit response(int code) : code(code) {}
        response(std::string body) : body(std::move(body)) {}
        response(json::wvalue&& json_value) : json_value(std::move(json_value))
        {
            json_mode();
        }
        response(int code, std::string body) : code(code), body(std::move(body)) {}
        response(const json::wvalue& json_value) : body(json::dump(json_value))
        {
            json_mode();
        }
        response(int code, const json::wvalue& json_value) : code(code), body(json::dump(json_value))
        {
            json_mode();
        }

        response(response&& r)
        {
            *this = std::move(r);
        }

        response& operator = (const response& r) = delete;

        response& operator = (response&& r) noexcept
        {
            body = std::move(r.body);
            json_value = std::move(r.json_value);
            code = r.code;
            headers = std::move(r.headers);
            completed_ = r.completed_;
            return *this;
        }

        bool is_completed() const noexcept
        {
            return completed_;
        }

        void clear()
        {
            body.clear();
            json_value.clear();
            code = 200;
            headers.clear();
            completed_ = false;
        }

        void redirect(const std::string& location)
        {
            code = 301;
            set_header("Location", location);
        }

        void write(const std::string& body_part)
        {
            body += body_part;
        }

        void end()
        {
            if (!completed_)
            {
                completed_ = true;

                if (complete_request_handler_)
                {
                    complete_request_handler_();
                }
            }
        }

        void end(const std::string& body_part)
        {
            body += body_part;
            end();
        }

        bool is_alive()
        {
            return is_alive_helper_ && is_alive_helper_();
        }

        private:
            bool completed_{};
            std::function<void()> complete_request_handler_;
            std::function<bool()> is_alive_helper_;


            void json_mode()
            {
                set_header("Content-Type", "application/json");
            }
    };
}


       




namespace crow
{

    struct CookieParser
    {
        struct context
        {
            std::unordered_map<std::string, std::string> jar;
            std::unordered_map<std::string, std::string> cookies_to_add;

            std::string get_cookie(const std::string& key) const
            {
                auto cookie = jar.find(key);
                if (cookie != jar.end())
                    return cookie->second;
                return {};
            }

            void set_cookie(const std::string& key, const std::string& value)
            {
                cookies_to_add.emplace(key, value);
            }
        };

        void before_handle(request& req, response& res, context& ctx)
        {
            int count = req.headers.count("Cookie");
            if (!count)
                return;
            if (count > 1)
            {
                res.code = 400;
                res.end();
                return;
            }
            std::string cookies = req.get_header_value("Cookie");
            size_t pos = 0;
            while(pos < cookies.size())
            {
                size_t pos_equal = cookies.find('=', pos);
                if (pos_equal == cookies.npos)
                    break;
                std::string name = cookies.substr(pos, pos_equal-pos);
                boost::trim(name);
                pos = pos_equal+1;
                while(pos < cookies.size() && cookies[pos] == ' ') pos++;
                if (pos == cookies.size())
                    break;

                size_t pos_semicolon = cookies.find(';', pos);
                std::string value = cookies.substr(pos, pos_semicolon-pos);

                boost::trim(value);
                if (value[0] == '"' && value[value.size()-1] == '"')
                {
                    value = value.substr(1, value.size()-2);
                }

                ctx.jar.emplace(std::move(name), std::move(value));

                pos = pos_semicolon;
                if (pos == cookies.npos)
                    break;
                pos++;
                while(pos < cookies.size() && cookies[pos] == ' ') pos++;
            }
        }

        void after_handle(request& , response& res, context& ctx)
        {
            for(auto& cookie:ctx.cookies_to_add)
            {
                if (cookie.second.empty())
                    res.add_header("Set-Cookie", cookie.first + "=\"\"");
                else
                    res.add_header("Set-Cookie", cookie.first + "=" + cookie.second);
            }
        }
    };

}


       









namespace crow
{
    class BaseRule
    {
    public:
        BaseRule(std::string rule)
            : rule_(std::move(rule))
        {
        }

        virtual ~BaseRule()
        {
        }

        virtual void validate() = 0;
        std::unique_ptr<BaseRule> upgrade()
        {
            if (rule_to_upgrade_)
                return std::move(rule_to_upgrade_);
            return {};
        }

        virtual void handle(const request&, response&, const routing_params&) = 0;
        virtual void handle_upgrade(const request&, response& res, SocketAdaptor&&)
        {
            res = response(404);
            res.end();
        }

        uint32_t get_methods()
        {
            return methods_;
        }

        template <typename F>
        void foreach_method(F f)
        {
            for(uint32_t method = 0, method_bit = 1; method < (uint32_t)HTTPMethod::InternalMethodCount; method++, method_bit<<=1)
            {
                if (methods_ & method_bit)
                    f(method);
            }
        }

        const std::string& rule() { return rule_; }

    protected:
        uint32_t methods_{1<<(int)HTTPMethod::Get};

        std::string rule_;
        std::string name_;

        std::unique_ptr<BaseRule> rule_to_upgrade_;

        friend class Router;
        template <typename T>
        friend struct RuleParameterTraits;
    };


    namespace detail
    {
        namespace routing_handler_call_helper
        {
            template <typename T, int Pos>
            struct call_pair
            {
                using type = T;
                static const int pos = Pos;
            };

            template <typename H1>
            struct call_params
            {
                H1& handler;
                const routing_params& params;
                const request& req;
                response& res;
            };

            template <typename F, int NInt, int NUint, int NDouble, int NString, typename S1, typename S2>
            struct call
            {
            };

            template <typename F, int NInt, int NUint, int NDouble, int NString, typename ... Args1, typename ... Args2>
            struct call<F, NInt, NUint, NDouble, NString, black_magic::S<int64_t, Args1...>, black_magic::S<Args2...>>
            {
                void operator()(F cparams)
                {
                    using pushed = typename black_magic::S<Args2...>::template push_back<call_pair<int64_t, NInt>>;
                    call<F, NInt+1, NUint, NDouble, NString,
                        black_magic::S<Args1...>, pushed>()(cparams);
                }
            };

            template <typename F, int NInt, int NUint, int NDouble, int NString, typename ... Args1, typename ... Args2>
            struct call<F, NInt, NUint, NDouble, NString, black_magic::S<uint64_t, Args1...>, black_magic::S<Args2...>>
            {
                void operator()(F cparams)
                {
                    using pushed = typename black_magic::S<Args2...>::template push_back<call_pair<uint64_t, NUint>>;
                    call<F, NInt, NUint+1, NDouble, NString,
                        black_magic::S<Args1...>, pushed>()(cparams);
                }
            };

            template <typename F, int NInt, int NUint, int NDouble, int NString, typename ... Args1, typename ... Args2>
            struct call<F, NInt, NUint, NDouble, NString, black_magic::S<double, Args1...>, black_magic::S<Args2...>>
            {
                void operator()(F cparams)
                {
                    using pushed = typename black_magic::S<Args2...>::template push_back<call_pair<double, NDouble>>;
                    call<F, NInt, NUint, NDouble+1, NString,
                        black_magic::S<Args1...>, pushed>()(cparams);
                }
            };

            template <typename F, int NInt, int NUint, int NDouble, int NString, typename ... Args1, typename ... Args2>
            struct call<F, NInt, NUint, NDouble, NString, black_magic::S<std::string, Args1...>, black_magic::S<Args2...>>
            {
                void operator()(F cparams)
                {
                    using pushed = typename black_magic::S<Args2...>::template push_back<call_pair<std::string, NString>>;
                    call<F, NInt, NUint, NDouble, NString+1,
                        black_magic::S<Args1...>, pushed>()(cparams);
                }
            };

            template <typename F, int NInt, int NUint, int NDouble, int NString, typename ... Args1>
            struct call<F, NInt, NUint, NDouble, NString, black_magic::S<>, black_magic::S<Args1...>>
            {
                void operator()(F cparams)
                {
                    cparams.handler(
                        cparams.req,
                        cparams.res,
                        cparams.params.template get<typename Args1::type>(Args1::pos)...
                    );
                }
            };

            template <typename Func, typename ... ArgsWrapped>
            struct Wrapped
            {
                template <typename ... Args>
                void set_(Func f, typename std::enable_if<
                    !std::is_same<typename std::tuple_element<0, std::tuple<Args..., void>>::type, const request&>::value
                , int>::type = 0)
                {
                    handler_ = (



                        [f]

                        (const request&, response& res, Args... args){
                            res = response(f(args...));
                            res.end();
                        });
                }

                template <typename Req, typename ... Args>
                struct req_handler_wrapper
                {
                    req_handler_wrapper(Func f)
                        : f(std::move(f))
                    {
                    }

                    void operator()(const request& req, response& res, Args... args)
                    {
                        res = response(f(req, args...));
                        res.end();
                    }

                    Func f;
                };

                template <typename ... Args>
                void set_(Func f, typename std::enable_if<
                        std::is_same<typename std::tuple_element<0, std::tuple<Args..., void>>::type, const request&>::value &&
                        !std::is_same<typename std::tuple_element<1, std::tuple<Args..., void, void>>::type, response&>::value
                        , int>::type = 0)
                {
                    handler_ = req_handler_wrapper<Args...>(std::move(f));






                }

                template <typename ... Args>
                void set_(Func f, typename std::enable_if<
                        std::is_same<typename std::tuple_element<0, std::tuple<Args..., void>>::type, const request&>::value &&
                        std::is_same<typename std::tuple_element<1, std::tuple<Args..., void, void>>::type, response&>::value
                        , int>::type = 0)
                {
                    handler_ = std::move(f);
                }

                template <typename ... Args>
                struct handler_type_helper
                {
                    using type = std::function<void(const crow::request&, crow::response&, Args...)>;
                    using args_type = black_magic::S<typename black_magic::promote_t<Args>...>;
                };

                template <typename ... Args>
                struct handler_type_helper<const request&, Args...>
                {
                    using type = std::function<void(const crow::request&, crow::response&, Args...)>;
                    using args_type = black_magic::S<typename black_magic::promote_t<Args>...>;
                };

                template <typename ... Args>
                struct handler_type_helper<const request&, response&, Args...>
                {
                    using type = std::function<void(const crow::request&, crow::response&, Args...)>;
                    using args_type = black_magic::S<typename black_magic::promote_t<Args>...>;
                };

                typename handler_type_helper<ArgsWrapped...>::type handler_;

                void operator()(const request& req, response& res, const routing_params& params)
                {
                    detail::routing_handler_call_helper::call<
                        detail::routing_handler_call_helper::call_params<
                            decltype(handler_)>,
                        0, 0, 0, 0,
                        typename handler_type_helper<ArgsWrapped...>::args_type,
                        black_magic::S<>
                    >()(
                        detail::routing_handler_call_helper::call_params<
                            decltype(handler_)>
                        {handler_, params, req, res}
                   );
                }
            };

        }
    }

    class WebSocketRule : public BaseRule
    {
        using self_t = WebSocketRule;
    public:
        WebSocketRule(std::string rule)
            : BaseRule(std::move(rule))
        {
        }

        void validate() override
        {
        }

        void handle(const request&, response& res, const routing_params&) override
        {
            res = response(404);
            res.end();
        }

        void handle_upgrade(const request& req, response&, SocketAdaptor&& adaptor) override
        {
            new crow::websocket::Connection<SocketAdaptor>(req, std::move(adaptor), open_handler_, message_handler_, close_handler_, error_handler_, accept_handler_);
        }







        template <typename Func>
        self_t& onopen(Func f)
        {
            open_handler_ = f;
            return *this;
        }

        template <typename Func>
        self_t& onmessage(Func f)
        {
            message_handler_ = f;
            return *this;
        }

        template <typename Func>
        self_t& onclose(Func f)
        {
            close_handler_ = f;
            return *this;
        }

        template <typename Func>
        self_t& onerror(Func f)
        {
            error_handler_ = f;
            return *this;
        }

        template <typename Func>
        self_t& onaccept(Func f)
        {
            accept_handler_ = f;
            return *this;
        }

    protected:
        std::function<void(crow::websocket::connection&)> open_handler_;
        std::function<void(crow::websocket::connection&, const std::string&, bool)> message_handler_;
        std::function<void(crow::websocket::connection&, const std::string&)> close_handler_;
        std::function<void(crow::websocket::connection&)> error_handler_;
        std::function<bool(const crow::request&)> accept_handler_;
    };

    template <typename T>
    struct RuleParameterTraits
    {
        using self_t = T;
        WebSocketRule& websocket()
        {
            auto p =new WebSocketRule(((self_t*)this)->rule_);
            ((self_t*)this)->rule_to_upgrade_.reset(p);
            return *p;
        }

        self_t& name(std::string name) noexcept
        {
            ((self_t*)this)->name_ = std::move(name);
            return (self_t&)*this;
        }

        self_t& methods(HTTPMethod method)
        {
            ((self_t*)this)->methods_ = 1 << (int)method;
            return (self_t&)*this;
        }

        template <typename ... MethodArgs>
        self_t& methods(HTTPMethod method, MethodArgs ... args_method)
        {
            methods(args_method...);
            ((self_t*)this)->methods_ |= 1 << (int)method;
            return (self_t&)*this;
        }

    };

    class DynamicRule : public BaseRule, public RuleParameterTraits<DynamicRule>
    {
    public:

        DynamicRule(std::string rule)
            : BaseRule(std::move(rule))
        {
        }

        void validate() override
        {
            if (!erased_handler_)
            {
                throw std::runtime_error(name_ + (!name_.empty() ? ": " : "") + "no handler for url " + rule_);
            }
        }

        void handle(const request& req, response& res, const routing_params& params) override
        {
            erased_handler_(req, res, params);
        }

        template <typename Func>
        void operator()(Func f)
        {



            using function_t = utility::function_traits<Func>;

            erased_handler_ = wrap(std::move(f), black_magic::gen_seq<function_t::arity>());
        }







        template <typename Func, unsigned ... Indices>

        std::function<void(const request&, response&, const routing_params&)>
        wrap(Func f, black_magic::seq<Indices...>)
        {



            using function_t = utility::function_traits<Func>;

            if (!black_magic::is_parameter_tag_compatible(
                black_magic::get_parameter_tag_runtime(rule_.c_str()),
                black_magic::compute_parameter_tag_from_args_list<
                    typename function_t::template arg<Indices>...>::value))
            {
                throw std::runtime_error("route_dynamic: Handler type is mismatched with URL parameters: " + rule_);
            }
            auto ret = detail::routing_handler_call_helper::Wrapped<Func, typename function_t::template arg<Indices>...>();
            ret.template set_<
                typename function_t::template arg<Indices>...
            >(std::move(f));
            return ret;
        }

        template <typename Func>
        void operator()(std::string name, Func&& f)
        {
            name_ = std::move(name);
            (*this).template operator()<Func>(std::forward(f));
        }
    private:
        std::function<void(const request&, response&, const routing_params&)> erased_handler_;

    };

    template <typename ... Args>
    class TaggedRule : public BaseRule, public RuleParameterTraits<TaggedRule<Args...>>
    {
    public:
        using self_t = TaggedRule<Args...>;

        TaggedRule(std::string rule)
            : BaseRule(std::move(rule))
        {
        }

        void validate() override
        {
            if (!handler_)
            {
                throw std::runtime_error(name_ + (!name_.empty() ? ": " : "") + "no handler for url " + rule_);
            }
        }

        template <typename Func>
        typename std::enable_if<black_magic::CallHelper<Func, black_magic::S<Args...>>::value, void>::type
        operator()(Func&& f)
        {
            static_assert(black_magic::CallHelper<Func, black_magic::S<Args...>>::value ||
                black_magic::CallHelper<Func, black_magic::S<crow::request, Args...>>::value ,
                "Handler type is mismatched with URL parameters");
            static_assert(!std::is_same<void, decltype(f(std::declval<Args>()...))>::value,
                "Handler function cannot have void return type; valid return types: string, int, crow::resposne, crow::json::wvalue");

            handler_ = (



                [f]

                (const request&, response& res, Args ... args){
                    res = response(f(args...));
                    res.end();
                });
        }

        template <typename Func>
        typename std::enable_if<
            !black_magic::CallHelper<Func, black_magic::S<Args...>>::value &&
            black_magic::CallHelper<Func, black_magic::S<crow::request, Args...>>::value,
            void>::type
        operator()(Func&& f)
        {
            static_assert(black_magic::CallHelper<Func, black_magic::S<Args...>>::value ||
                black_magic::CallHelper<Func, black_magic::S<crow::request, Args...>>::value,
                "Handler type is mismatched with URL parameters");
            static_assert(!std::is_same<void, decltype(f(std::declval<crow::request>(), std::declval<Args>()...))>::value,
                "Handler function cannot have void return type; valid return types: string, int, crow::resposne, crow::json::wvalue");

            handler_ = (



                [f]

                (const crow::request& req, crow::response& res, Args ... args){
                    res = response(f(req, args...));
                    res.end();
                });
        }

        template <typename Func>
        typename std::enable_if<
            !black_magic::CallHelper<Func, black_magic::S<Args...>>::value &&
            !black_magic::CallHelper<Func, black_magic::S<crow::request, Args...>>::value,
            void>::type
        operator()(Func&& f)
        {
            static_assert(black_magic::CallHelper<Func, black_magic::S<Args...>>::value ||
                black_magic::CallHelper<Func, black_magic::S<crow::request, Args...>>::value ||
                black_magic::CallHelper<Func, black_magic::S<crow::request, crow::response&, Args...>>::value
                ,
                "Handler type is mismatched with URL parameters");
            static_assert(std::is_same<void, decltype(f(std::declval<crow::request>(), std::declval<crow::response&>(), std::declval<Args>()...))>::value,
                "Handler function with response argument should have void return type");

                handler_ = std::move(f);
        }

        template <typename Func>
        void operator()(std::string name, Func&& f)
        {
            name_ = std::move(name);
            (*this).template operator()<Func>(std::forward(f));
        }

        void handle(const request& req, response& res, const routing_params& params) override
        {
            detail::routing_handler_call_helper::call<
                detail::routing_handler_call_helper::call_params<
                    decltype(handler_)>,
                0, 0, 0, 0,
                black_magic::S<Args...>,
                black_magic::S<>
            >()(
                detail::routing_handler_call_helper::call_params<
                    decltype(handler_)>
                {handler_, params, req, res}
            );
        }

    private:
        std::function<void(const crow::request&, crow::response&, Args...)> handler_;

    };

    const int RULE_SPECIAL_REDIRECT_SLASH = 1;

    class Trie
    {
    public:
        struct Node
        {
            unsigned rule_index{};
            std::array<unsigned, (int)ParamType::MAX> param_childrens{};
            std::unordered_map<std::string, unsigned> children;

            bool IsSimpleNode() const
            {
                return
                    !rule_index &&
                    std::all_of(
                        std::begin(param_childrens),
                        std::end(param_childrens),
                        [](unsigned x){ return !x; });
            }
        };

        Trie() : nodes_(1)
        {
        }

private:
        void optimizeNode(Node* node)
        {
            for(auto x : node->param_childrens)
            {
                if (!x)
                    continue;
                Node* child = &nodes_[x];
                optimizeNode(child);
            }
            if (node->children.empty())
                return;
            bool mergeWithChild = true;
            for(auto& kv : node->children)
            {
                Node* child = &nodes_[kv.second];
                if (!child->IsSimpleNode())
                {
                    mergeWithChild = false;
                    break;
                }
            }
            if (mergeWithChild)
            {
                decltype(node->children) merged;
                for(auto& kv : node->children)
                {
                    Node* child = &nodes_[kv.second];
                    for(auto& child_kv : child->children)
                    {
                        merged[kv.first + child_kv.first] = child_kv.second;
                    }
                }
                node->children = std::move(merged);
                optimizeNode(node);
            }
            else
            {
                for(auto& kv : node->children)
                {
                    Node* child = &nodes_[kv.second];
                    optimizeNode(child);
                }
            }
        }

        void optimize()
        {
            optimizeNode(head());
        }

public:
        void validate()
        {
            if (!head()->IsSimpleNode())
                throw std::runtime_error("Internal error: Trie header should be simple!");
            optimize();
        }

        std::pair<unsigned, routing_params> find(const std::string& req_url, const Node* node = nullptr, unsigned pos = 0, routing_params* params = nullptr) const
        {
            routing_params empty;
            if (params == nullptr)
                params = &empty;

            unsigned found{};
            routing_params match_params;

            if (node == nullptr)
                node = head();
            if (pos == req_url.size())
                return {node->rule_index, *params};

            auto update_found = [&found, &match_params](std::pair<unsigned, routing_params>& ret)
            {
                if (ret.first && (!found || found > ret.first))
                {
                    found = ret.first;
                    match_params = std::move(ret.second);
                }
            };

            if (node->param_childrens[(int)ParamType::INT])
            {
                char c = req_url[pos];
                if ((c >= '0' && c <= '9') || c == '+' || c == '-')
                {
                    char* eptr;
                    errno = 0;
                    long long int value = strtoll(req_url.data()+pos, &eptr, 10);
                    if (errno != ERANGE && eptr != req_url.data()+pos)
                    {
                        params->int_params.push_back(value);
                        auto ret = find(req_url, &nodes_[node->param_childrens[(int)ParamType::INT]], eptr - req_url.data(), params);
                        update_found(ret);
                        params->int_params.pop_back();
                    }
                }
            }

            if (node->param_childrens[(int)ParamType::UINT])
            {
                char c = req_url[pos];
                if ((c >= '0' && c <= '9') || c == '+')
                {
                    char* eptr;
                    errno = 0;
                    unsigned long long int value = strtoull(req_url.data()+pos, &eptr, 10);
                    if (errno != ERANGE && eptr != req_url.data()+pos)
                    {
                        params->uint_params.push_back(value);
                        auto ret = find(req_url, &nodes_[node->param_childrens[(int)ParamType::UINT]], eptr - req_url.data(), params);
                        update_found(ret);
                        params->uint_params.pop_back();
                    }
                }
            }

            if (node->param_childrens[(int)ParamType::DOUBLE])
            {
                char c = req_url[pos];
                if ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')
                {
                    char* eptr;
                    errno = 0;
                    double value = strtod(req_url.data()+pos, &eptr);
                    if (errno != ERANGE && eptr != req_url.data()+pos)
                    {
                        params->double_params.push_back(value);
                        auto ret = find(req_url, &nodes_[node->param_childrens[(int)ParamType::DOUBLE]], eptr - req_url.data(), params);
                        update_found(ret);
                        params->double_params.pop_back();
                    }
                }
            }

            if (node->param_childrens[(int)ParamType::STRING])
            {
                size_t epos = pos;
                for(; epos < req_url.size(); epos ++)
                {
                    if (req_url[epos] == '/')
                        break;
                }

                if (epos != pos)
                {
                    params->string_params.push_back(req_url.substr(pos, epos-pos));
                    auto ret = find(req_url, &nodes_[node->param_childrens[(int)ParamType::STRING]], epos, params);
                    update_found(ret);
                    params->string_params.pop_back();
                }
            }

            if (node->param_childrens[(int)ParamType::PATH])
            {
                size_t epos = req_url.size();

                if (epos != pos)
                {
                    params->string_params.push_back(req_url.substr(pos, epos-pos));
                    auto ret = find(req_url, &nodes_[node->param_childrens[(int)ParamType::PATH]], epos, params);
                    update_found(ret);
                    params->string_params.pop_back();
                }
            }

            for(auto& kv : node->children)
            {
                const std::string& fragment = kv.first;
                const Node* child = &nodes_[kv.second];

                if (req_url.compare(pos, fragment.size(), fragment) == 0)
                {
                    auto ret = find(req_url, child, pos + fragment.size(), params);
                    update_found(ret);
                }
            }

            return {found, match_params};
        }

        void add(const std::string& url, unsigned rule_index)
        {
            unsigned idx{0};

            for(unsigned i = 0; i < url.size(); i ++)
            {
                char c = url[i];
                if (c == '<')
                {
                    static struct ParamTraits
                    {
                        ParamType type;
                        std::string name;
                    } paramTraits[] =
                    {
                        { ParamType::INT, "<int>" },
                        { ParamType::UINT, "<uint>" },
                        { ParamType::DOUBLE, "<float>" },
                        { ParamType::DOUBLE, "<double>" },
                        { ParamType::STRING, "<str>" },
                        { ParamType::STRING, "<string>" },
                        { ParamType::PATH, "<path>" },
                    };

                    for(auto& x:paramTraits)
                    {
                        if (url.compare(i, x.name.size(), x.name) == 0)
                        {
                            if (!nodes_[idx].param_childrens[(int)x.type])
                            {
                                auto new_node_idx = new_node();
                                nodes_[idx].param_childrens[(int)x.type] = new_node_idx;
                            }
                            idx = nodes_[idx].param_childrens[(int)x.type];
                            i += x.name.size();
                            break;
                        }
                    }

                    i --;
                }
                else
                {
                    std::string piece(&c, 1);
                    if (!nodes_[idx].children.count(piece))
                    {
                        auto new_node_idx = new_node();
                        nodes_[idx].children.emplace(piece, new_node_idx);
                    }
                    idx = nodes_[idx].children[piece];
                }
            }
            if (nodes_[idx].rule_index)
                throw std::runtime_error("handler already exists for " + url);
            nodes_[idx].rule_index = rule_index;
        }
    private:
        void debug_node_print(Node* n, int level)
        {
            for(int i = 0; i < (int)ParamType::MAX; i ++)
            {
                if (n->param_childrens[i])
                {
                    if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << std::string(2*level, ' ') ;
                    switch((ParamType)i)
                    {
                        case ParamType::INT:
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "<int>";
                            break;
                        case ParamType::UINT:
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "<uint>";
                            break;
                        case ParamType::DOUBLE:
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "<float>";
                            break;
                        case ParamType::STRING:
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "<str>";
                            break;
                        case ParamType::PATH:
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "<path>";
                            break;
                        default:
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "<ERROR>";
                            break;
                    }

                    debug_node_print(&nodes_[n->param_childrens[i]], level+1);
                }
            }
            for(auto& kv : n->children)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << std::string(2*level, ' ') << kv.first;
                debug_node_print(&nodes_[kv.second], level+1);
            }
        }

    public:
        void debug_print()
        {
            debug_node_print(head(), 0);
        }

    private:
        const Node* head() const
        {
            return &nodes_.front();
        }

        Node* head()
        {
            return &nodes_.front();
        }

        unsigned new_node()
        {
            nodes_.resize(nodes_.size()+1);
            return nodes_.size() - 1;
        }

        std::vector<Node> nodes_;
    };

    class Router
    {
    public:
        Router()
        {
        }

        DynamicRule& new_rule_dynamic(const std::string& rule)
        {
            auto ruleObject = new DynamicRule(rule);
            all_rules_.emplace_back(ruleObject);

            return *ruleObject;
        }

        template <uint64_t N>
        typename black_magic::arguments<N>::type::template rebind<TaggedRule>& new_rule_tagged(const std::string& rule)
        {
            using RuleT = typename black_magic::arguments<N>::type::template rebind<TaggedRule>;

            auto ruleObject = new RuleT(rule);
            all_rules_.emplace_back(ruleObject);

            return *ruleObject;
        }

        void internal_add_rule_object(const std::string& rule, BaseRule* ruleObject)
        {
            bool has_trailing_slash = false;
            std::string rule_without_trailing_slash;
            if (rule.size() > 1 && rule.back() == '/')
            {
                has_trailing_slash = true;
                rule_without_trailing_slash = rule;
                rule_without_trailing_slash.pop_back();
            }

            ruleObject->foreach_method([&](int method)
                    {
                        per_methods_[method].rules.emplace_back(ruleObject);
                        per_methods_[method].trie.add(rule, per_methods_[method].rules.size() - 1);



                        if (has_trailing_slash)
                        {
                            per_methods_[method].trie.add(rule_without_trailing_slash, RULE_SPECIAL_REDIRECT_SLASH);
                        }
                    });

        }

        void validate()
        {
            for(auto& rule:all_rules_)
            {
                if (rule)
                {
                    auto upgraded = rule->upgrade();
                    if (upgraded)
                        rule = std::move(upgraded);
                    rule->validate();
                    internal_add_rule_object(rule->rule(), rule.get());
                }
            }
            for(auto& per_method:per_methods_)
            {
                per_method.trie.validate();
            }
        }

        template <typename Adaptor>
        void handle_upgrade(const request& req, response& res, Adaptor&& adaptor)
        {
            if (req.method >= HTTPMethod::InternalMethodCount)
                return;
            auto& per_method = per_methods_[(int)req.method];
            auto& trie = per_method.trie;
            auto& rules = per_method.rules;

            auto found = trie.find(req.url);
            unsigned rule_index = found.first;
            if (!rule_index)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "Cannot match rules " << req.url << ' ' << method_name(req.method);
                res = response(404);
                res.end();
                return;
            }

            if (rule_index >= rules.size())
                throw std::runtime_error("Trie internal structure corrupted!");

            if (rule_index == RULE_SPECIAL_REDIRECT_SLASH)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << "Redirecting to a url with trailing slash: " << req.url;
                res = response(301);


                if (req.get_header_value("Host").empty())
                {
                    res.add_header("Location", req.url + "/");
                }
                else
                {
                    res.add_header("Location", "http://" + req.get_header_value("Host") + req.url + "/");
                }
                res.end();
                return;
            }

            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "Matched rule (upgrade) '" << rules[rule_index]->rule_ << "' " << (uint32_t)req.method << " / " << rules[rule_index]->get_methods();


            try
            {
                rules[rule_index]->handle_upgrade(req, res, std::move(adaptor));
            }
            catch(std::exception& e)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Error) crow::logger("ERROR   ", crow::LogLevel::Error) << "An uncaught exception occurred: " << e.what();
                res = response(500);
                res.end();
                return;
            }
            catch(...)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Error) crow::logger("ERROR   ", crow::LogLevel::Error) << "An uncaught exception occurred. The type was unknown so no information was available.";
                res = response(500);
                res.end();
                return;
            }
        }

        void handle(const request& req, response& res)
        {
            if (req.method >= HTTPMethod::InternalMethodCount)
                return;
            auto& per_method = per_methods_[(int)req.method];
            auto& trie = per_method.trie;
            auto& rules = per_method.rules;

            auto found = trie.find(req.url);

            unsigned rule_index = found.first;

            if (!rule_index)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "Cannot match rules " << req.url << ' ' << method_name(req.method);
                res = response(404);
                res.end();
                return;
            }

            if (rule_index >= rules.size())
                throw std::runtime_error("Trie internal structure corrupted!");

            if (rule_index == RULE_SPECIAL_REDIRECT_SLASH)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << "Redirecting to a url with trailing slash: " << req.url;
                res = response(301);


                if (req.get_header_value("Host").empty())
                {
                    res.add_header("Location", req.url + "/");
                }
                else
                {
                    res.add_header("Location", "http://" + req.get_header_value("Host") + req.url + "/");
                }
                res.end();
                return;
            }

            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "Matched rule '" << rules[rule_index]->rule_ << "' " << (uint32_t)req.method << " / " << rules[rule_index]->get_methods();


            try
            {
                rules[rule_index]->handle(req, res, found.second);
            }
            catch(std::exception& e)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Error) crow::logger("ERROR   ", crow::LogLevel::Error) << "An uncaught exception occurred: " << e.what();
                res = response(500);
                res.end();
                return;
            }
            catch(...)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Error) crow::logger("ERROR   ", crow::LogLevel::Error) << "An uncaught exception occurred. The type was unknown so no information was available.";
                res = response(500);
                res.end();
                return;
            }
        }

        void debug_print()
        {
            for(int i = 0; i < (int)HTTPMethod::InternalMethodCount; i ++)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << method_name((HTTPMethod)i);
                per_methods_[i].trie.debug_print();
            }
        }

    private:
        struct PerMethod
        {
            std::vector<BaseRule*> rules;
            Trie trie;


            PerMethod() : rules(2) {}
        };
        std::array<PerMethod, (int)HTTPMethod::InternalMethodCount> per_methods_;
        std::vector<std::unique_ptr<BaseRule>> all_rules_;
    };
}


       





namespace crow
{
    namespace detail
    {
        template <typename ... Middlewares>
        struct partial_context
            : public black_magic::pop_back<Middlewares...>::template rebind<partial_context>
            , public black_magic::last_element_type<Middlewares...>::type::context
        {
            using parent_context = typename black_magic::pop_back<Middlewares...>::template rebind<::crow::detail::partial_context>;
            template <int N>
            using partial = typename std::conditional<N == sizeof...(Middlewares)-1, partial_context, typename parent_context::template partial<N>>::type;

            template <typename T>
            typename T::context& get()
            {
                return static_cast<typename T::context&>(*this);
            }
        };

        template <>
        struct partial_context<>
        {
            template <int>
            using partial = partial_context;
        };

        template <int N, typename Context, typename Container, typename CurrentMW, typename ... Middlewares>
        bool middleware_call_helper(Container& middlewares, request& req, response& res, Context& ctx);

        template <typename ... Middlewares>
        struct context : private partial_context<Middlewares...>

        {
            template <int N, typename Context, typename Container>
            friend typename std::enable_if<(N==0)>::type after_handlers_call_helper(Container& middlewares, Context& ctx, request& req, response& res);
            template <int N, typename Context, typename Container>
            friend typename std::enable_if<(N>0)>::type after_handlers_call_helper(Container& middlewares, Context& ctx, request& req, response& res);

            template <int N, typename Context, typename Container, typename CurrentMW, typename ... Middlewares2>
            friend bool middleware_call_helper(Container& middlewares, request& req, response& res, Context& ctx);

            template <typename T>
            typename T::context& get()
            {
                return static_cast<typename T::context&>(*this);
            }

            template <int N>
            using partial = typename partial_context<Middlewares...>::template partial<N>;
        };
    }
}


       








namespace crow
{
    using namespace boost;
    using tcp = asio::ip::tcp;

    namespace detail
    {
        template <typename MW>
        struct check_before_handle_arity_3_const
        {
            template <typename T,
                void (T::*)(request&, response&, typename MW::context&) const = &T::before_handle
            >
            struct get
            { };
        };

        template <typename MW>
        struct check_before_handle_arity_3
        {
            template <typename T,
                void (T::*)(request&, response&, typename MW::context&) = &T::before_handle
            >
            struct get
            { };
        };

        template <typename MW>
        struct check_after_handle_arity_3_const
        {
            template <typename T,
                void (T::*)(request&, response&, typename MW::context&) const = &T::after_handle
            >
            struct get
            { };
        };

        template <typename MW>
        struct check_after_handle_arity_3
        {
            template <typename T,
                void (T::*)(request&, response&, typename MW::context&) = &T::after_handle
            >
            struct get
            { };
        };

        template <typename T>
        struct is_before_handle_arity_3_impl
        {
            template <typename C>
            static std::true_type f(typename check_before_handle_arity_3_const<T>::template get<C>*);

            template <typename C>
            static std::true_type f(typename check_before_handle_arity_3<T>::template get<C>*);

            template <typename C>
            static std::false_type f(...);

        public:
            static const bool value = decltype(f<T>(nullptr))::value;
        };

        template <typename T>
        struct is_after_handle_arity_3_impl
        {
            template <typename C>
            static std::true_type f(typename check_after_handle_arity_3_const<T>::template get<C>*);

            template <typename C>
            static std::true_type f(typename check_after_handle_arity_3<T>::template get<C>*);

            template <typename C>
            static std::false_type f(...);

        public:
            static const bool value = decltype(f<T>(nullptr))::value;
        };

        template <typename MW, typename Context, typename ParentContext>
        typename std::enable_if<!is_before_handle_arity_3_impl<MW>::value>::type
        before_handler_call(MW& mw, request& req, response& res, Context& ctx, ParentContext& )
        {
            mw.before_handle(req, res, ctx.template get<MW>(), ctx);
        }

        template <typename MW, typename Context, typename ParentContext>
        typename std::enable_if<is_before_handle_arity_3_impl<MW>::value>::type
        before_handler_call(MW& mw, request& req, response& res, Context& ctx, ParentContext& )
        {
            mw.before_handle(req, res, ctx.template get<MW>());
        }

        template <typename MW, typename Context, typename ParentContext>
        typename std::enable_if<!is_after_handle_arity_3_impl<MW>::value>::type
        after_handler_call(MW& mw, request& req, response& res, Context& ctx, ParentContext& )
        {
            mw.after_handle(req, res, ctx.template get<MW>(), ctx);
        }

        template <typename MW, typename Context, typename ParentContext>
        typename std::enable_if<is_after_handle_arity_3_impl<MW>::value>::type
        after_handler_call(MW& mw, request& req, response& res, Context& ctx, ParentContext& )
        {
            mw.after_handle(req, res, ctx.template get<MW>());
        }

        template <int N, typename Context, typename Container, typename CurrentMW, typename ... Middlewares>
        bool middleware_call_helper(Container& middlewares, request& req, response& res, Context& ctx)
        {
            using parent_context_t = typename Context::template partial<N-1>;
            before_handler_call<CurrentMW, Context, parent_context_t>(std::get<N>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));

            if (res.is_completed())
            {
                after_handler_call<CurrentMW, Context, parent_context_t>(std::get<N>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));
                return true;
            }

            if (middleware_call_helper<N+1, Context, Container, Middlewares...>(middlewares, req, res, ctx))
            {
                after_handler_call<CurrentMW, Context, parent_context_t>(std::get<N>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));
                return true;
            }

            return false;
        }

        template <int N, typename Context, typename Container>
        bool middleware_call_helper(Container& , request& , response& , Context& )
        {
            return false;
        }

        template <int N, typename Context, typename Container>
        typename std::enable_if<(N<0)>::type
        after_handlers_call_helper(Container& , Context& , request& , response& )
        {
        }

        template <int N, typename Context, typename Container>
        typename std::enable_if<(N==0)>::type after_handlers_call_helper(Container& middlewares, Context& ctx, request& req, response& res)
        {
            using parent_context_t = typename Context::template partial<N-1>;
            using CurrentMW = typename std::tuple_element<N, typename std::remove_reference<Container>::type>::type;
            after_handler_call<CurrentMW, Context, parent_context_t>(std::get<N>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));
        }

        template <int N, typename Context, typename Container>
        typename std::enable_if<(N>0)>::type after_handlers_call_helper(Container& middlewares, Context& ctx, request& req, response& res)
        {
            using parent_context_t = typename Context::template partial<N-1>;
            using CurrentMW = typename std::tuple_element<N, typename std::remove_reference<Container>::type>::type;
            after_handler_call<CurrentMW, Context, parent_context_t>(std::get<N>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));
            after_handlers_call_helper<N-1, Context, Container>(middlewares, ctx, req, res);
        }
    }




    template <typename Adaptor, typename Handler, typename ... Middlewares>
    class Connection
    {
    public:
        Connection(
            boost::asio::io_service& io_service,
            Handler* handler,
            const std::string& server_name,
            std::tuple<Middlewares...>* middlewares,
            std::function<std::string()>& get_cached_date_str_f,
            detail::dumb_timer_queue& timer_queue,
            typename Adaptor::context* adaptor_ctx_
            )
            : adaptor_(io_service, adaptor_ctx_),
            handler_(handler),
            parser_(this),
            server_name_(server_name),
            middlewares_(middlewares),
            get_cached_date_str(get_cached_date_str_f),
            timer_queue(timer_queue)
        {




        }

        ~Connection()
        {
            res.complete_request_handler_ = nullptr;
            cancel_deadline_timer();




        }

        decltype(std::declval<Adaptor>().raw_socket())& socket()
        {
            return adaptor_.raw_socket();
        }

        void start()
        {
            adaptor_.start([this](const boost::system::error_code& ec) {
                if (!ec)
                {
                    start_deadline();

                    do_read();
                }
                else
                {
                    check_destroy();
                }
            });
        }

        void handle_header()
        {

            if (parser_.check_version(1, 1) && parser_.headers.count("expect") && get_header_value(parser_.headers, "expect") == "100-continue")
            {
                buffers_.clear();
                static std::string expect_100_continue = "HTTP/1.1 100 Continue\r\n\r\n";
                buffers_.emplace_back(expect_100_continue.data(), expect_100_continue.size());
                do_write();
            }
        }

        void handle()
        {
            cancel_deadline_timer();
            bool is_invalid_request = false;
            add_keep_alive_ = false;

            req_ = std::move(parser_.to_request());
            request& req = req_;

            if (parser_.check_version(1, 0))
            {

                if (req.headers.count("connection"))
                {
                    if (boost::iequals(req.get_header_value("connection"),"Keep-Alive"))
                        add_keep_alive_ = true;
                }
                else
                    close_connection_ = true;
            }
            else if (parser_.check_version(1, 1))
            {

                if (req.headers.count("connection"))
                {
                    if (req.get_header_value("connection") == "close")
                        close_connection_ = true;
                    else if (boost::iequals(req.get_header_value("connection"),"Keep-Alive"))
                        add_keep_alive_ = true;
                }
                if (!req.headers.count("host"))
                {
                    is_invalid_request = true;
                    res = response(400);
                }
    if (parser_.is_upgrade())
    {
     if (req.get_header_value("upgrade") == "h2c")
     {


     }
                    else
                    {
                        close_connection_ = true;
                        handler_->handle_upgrade(req, res, std::move(adaptor_));
                        return;
                    }
    }
            }

            if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << "Request: " << boost::lexical_cast<std::string>(adaptor_.remote_endpoint()) << " " << this << " HTTP/" << parser_.http_major << "." << parser_.http_minor << ' '
             << method_name(req.method) << " " << req.url;


            need_to_call_after_handlers_ = false;
            if (!is_invalid_request)
            {
                res.complete_request_handler_ = []{};
                res.is_alive_helper_ = [this]()->bool{ return adaptor_.is_open(); };

                ctx_ = detail::context<Middlewares...>();
                req.middleware_context = (void*)&ctx_;
                req.io_service = &adaptor_.get_io_service();
                detail::middleware_call_helper<0, decltype(ctx_), decltype(*middlewares_), Middlewares...>(*middlewares_, req, res, ctx_);

                if (!res.completed_)
                {
                    res.complete_request_handler_ = [this]{ this->complete_request(); };
                    need_to_call_after_handlers_ = true;
                    handler_->handle(req, res);
                    if (add_keep_alive_)
                        res.set_header("connection", "Keep-Alive");
                }
                else
                {
                    complete_request();
                }
            }
            else
            {
                complete_request();
            }
        }

        void complete_request()
        {
            if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << "Response: " << this << ' ' << req_.raw_url << ' ' << res.code << ' ' << close_connection_;

            if (need_to_call_after_handlers_)
            {
                need_to_call_after_handlers_ = false;


                detail::after_handlers_call_helper<
                    ((int)sizeof...(Middlewares)-1),
                    decltype(ctx_),
                    decltype(*middlewares_)>
                (*middlewares_, ctx_, req_, res);
            }


            res.complete_request_handler_ = nullptr;

            if (!adaptor_.is_open())
            {


                return;
            }

            static std::unordered_map<int, std::string> statusCodes = {
                {200, "HTTP/1.1 200 OK\r\n"},
                {201, "HTTP/1.1 201 Created\r\n"},
                {202, "HTTP/1.1 202 Accepted\r\n"},
                {204, "HTTP/1.1 204 No Content\r\n"},

                {300, "HTTP/1.1 300 Multiple Choices\r\n"},
                {301, "HTTP/1.1 301 Moved Permanently\r\n"},
                {302, "HTTP/1.1 302 Moved Temporarily\r\n"},
                {304, "HTTP/1.1 304 Not Modified\r\n"},

                {400, "HTTP/1.1 400 Bad Request\r\n"},
                {401, "HTTP/1.1 401 Unauthorized\r\n"},
                {403, "HTTP/1.1 403 Forbidden\r\n"},
                {404, "HTTP/1.1 404 Not Found\r\n"},
                {413, "HTTP/1.1 413 Payload Too Large\r\n"},
                {422, "HTTP/1.1 422 Unprocessable Entity\r\n"},
                {429, "HTTP/1.1 429 Too Many Requests\r\n"},

                {500, "HTTP/1.1 500 Internal Server Error\r\n"},
                {501, "HTTP/1.1 501 Not Implemented\r\n"},
                {502, "HTTP/1.1 502 Bad Gateway\r\n"},
                {503, "HTTP/1.1 503 Service Unavailable\r\n"},
            };

            static std::string seperator = ": ";
            static std::string crlf = "\r\n";

            buffers_.clear();
            buffers_.reserve(4*(res.headers.size()+5)+3);

            if (res.body.empty() && res.json_value.t() == json::type::Object)
            {
                res.body = json::dump(res.json_value);
            }

            if (!statusCodes.count(res.code))
                res.code = 500;
            {
                auto& status = statusCodes.find(res.code)->second;
                buffers_.emplace_back(status.data(), status.size());
            }

            if (res.code >= 400 && res.body.empty())
                res.body = statusCodes[res.code].substr(9);

            for(auto& kv : res.headers)
            {
                buffers_.emplace_back(kv.first.data(), kv.first.size());
                buffers_.emplace_back(seperator.data(), seperator.size());
                buffers_.emplace_back(kv.second.data(), kv.second.size());
                buffers_.emplace_back(crlf.data(), crlf.size());

            }

            if (!res.headers.count("content-length"))
            {
                content_length_ = std::to_string(res.body.size());
                static std::string content_length_tag = "Content-Length: ";
                buffers_.emplace_back(content_length_tag.data(), content_length_tag.size());
                buffers_.emplace_back(content_length_.data(), content_length_.size());
                buffers_.emplace_back(crlf.data(), crlf.size());
            }
            if (!res.headers.count("server"))
            {
                static std::string server_tag = "Server: ";
                buffers_.emplace_back(server_tag.data(), server_tag.size());
                buffers_.emplace_back(server_name_.data(), server_name_.size());
                buffers_.emplace_back(crlf.data(), crlf.size());
            }
            if (!res.headers.count("date"))
            {
                static std::string date_tag = "Date: ";
                date_str_ = get_cached_date_str();
                buffers_.emplace_back(date_tag.data(), date_tag.size());
                buffers_.emplace_back(date_str_.data(), date_str_.size());
                buffers_.emplace_back(crlf.data(), crlf.size());
            }
            if (add_keep_alive_)
            {
                static std::string keep_alive_tag = "Connection: Keep-Alive";
                buffers_.emplace_back(keep_alive_tag.data(), keep_alive_tag.size());
                buffers_.emplace_back(crlf.data(), crlf.size());
            }

            buffers_.emplace_back(crlf.data(), crlf.size());
            res_body_copy_.swap(res.body);
            buffers_.emplace_back(res_body_copy_.data(), res_body_copy_.size());

            do_write();

            if (need_to_start_read_after_complete_)
            {
                need_to_start_read_after_complete_ = false;
                start_deadline();
                do_read();
            }
        }

    private:
        void do_read()
        {

            is_reading = true;
            adaptor_.socket().async_read_some(boost::asio::buffer(buffer_),
                [this](const boost::system::error_code& ec, std::size_t bytes_transferred)
                {
                    bool error_while_reading = true;
                    if (!ec)
                    {
                        bool ret = parser_.feed(buffer_.data(), bytes_transferred);
                        if (ret && adaptor_.is_open())
                        {
                            error_while_reading = false;
                        }
                    }

                    if (error_while_reading)
                    {
                        cancel_deadline_timer();
                        parser_.done();
                        adaptor_.close();
                        is_reading = false;
                        if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " from read(1)";
                        check_destroy();
                    }
                    else if (close_connection_)
                    {
                        cancel_deadline_timer();
                        parser_.done();
                        is_reading = false;
                        check_destroy();

                    }
                    else if (!need_to_call_after_handlers_)
                    {
                        start_deadline();
                        do_read();
                    }
                    else
                    {

                        need_to_start_read_after_complete_ = true;
                    }
                });
        }

        void do_write()
        {

            is_writing = true;
            boost::asio::async_write(adaptor_.socket(), buffers_,
                [&](const boost::system::error_code& ec, std::size_t )
                {
                    is_writing = false;
                    res.clear();
                    res_body_copy_.clear();
                    if (!ec)
                    {
                        if (close_connection_)
                        {
                            adaptor_.close();
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " from write(1)";
                            check_destroy();
                        }
                    }
                    else
                    {
                        if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " from write(2)";
                        check_destroy();
                    }
                });
        }

        void check_destroy()
        {
            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " is_reading " << is_reading << " is_writing " << is_writing;
            if (!is_reading && !is_writing)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " delete (idle) ";
                delete this;
            }
        }

        void cancel_deadline_timer()
        {
            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " timer cancelled: " << timer_cancel_key_.first << ' ' << timer_cancel_key_.second;
            timer_queue.cancel(timer_cancel_key_);
        }

        void start_deadline( )
        {
            cancel_deadline_timer();

            timer_cancel_key_ = timer_queue.add([this]
            {
                if (!adaptor_.is_open())
                {
                    return;
                }
                adaptor_.close();
            });
            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " timer added: " << timer_cancel_key_.first << ' ' << timer_cancel_key_.second;
        }

    private:
        Adaptor adaptor_;
        Handler* handler_;

        boost::array<char, 4096> buffer_;

        HTTPParser<Connection> parser_;
        request req_;
        response res;

        bool close_connection_ = false;

        const std::string& server_name_;
        std::vector<boost::asio::const_buffer> buffers_;

        std::string content_length_;
        std::string date_str_;
        std::string res_body_copy_;


        detail::dumb_timer_queue::key timer_cancel_key_;

        bool is_reading{};
        bool is_writing{};
        bool need_to_call_after_handlers_{};
        bool need_to_start_read_after_complete_{};
        bool add_keep_alive_{};

        std::tuple<Middlewares...>* middlewares_;
        detail::context<Middlewares...> ctx_;

        std::function<std::string()>& get_cached_date_str;
        detail::dumb_timer_queue& timer_queue;
    };

}


       


















namespace crow
{
    using namespace boost;
    using tcp = asio::ip::tcp;

    template <typename Handler, typename Adaptor = SocketAdaptor, typename ... Middlewares>
    class Server
    {
    public:
    Server(Handler* handler, std::string bindaddr, uint16_t port, std::tuple<Middlewares...>* middlewares = nullptr, uint16_t concurrency = 1, typename Adaptor::context* adaptor_ctx = nullptr)
            : acceptor_(io_service_, tcp::endpoint(boost::asio::ip::address::from_string(bindaddr), port)),
            signals_(io_service_, SIGINT, SIGTERM),
            tick_timer_(io_service_),
            handler_(handler),
            concurrency_(concurrency),
            port_(port),
            bindaddr_(bindaddr),
            middlewares_(middlewares),
            adaptor_ctx_(adaptor_ctx)
        {
        }

        void set_tick_function(std::chrono::milliseconds d, std::function<void()> f)
        {
            tick_interval_ = d;
            tick_function_ = f;
        }

        void on_tick()
        {
            tick_function_();
            tick_timer_.expires_from_now(boost::posix_time::milliseconds(tick_interval_.count()));
            tick_timer_.async_wait([this](const boost::system::error_code& ec)
                    {
                        if (ec)
                            return;
                        on_tick();
                    });
        }

        void run()
        {
            if (concurrency_ < 0)
                concurrency_ = 1;

            for(int i = 0; i < concurrency_; i++)
                io_service_pool_.emplace_back(new boost::asio::io_service());
            get_cached_date_str_pool_.resize(concurrency_);
            timer_queue_pool_.resize(concurrency_);

            std::vector<std::future<void>> v;
            std::atomic<int> init_count(0);
            for(uint16_t i = 0; i < concurrency_; i ++)
                v.push_back(
                        std::async(std::launch::async, [this, i, &init_count]{


                            auto last = std::chrono::steady_clock::now();

                            std::string date_str;
                            auto update_date_str = [&]
                            {
                                auto last_time_t = time(0);
                                tm my_tm;




                                gmtime_r(&last_time_t, &my_tm);

                                date_str.resize(100);
                                size_t date_str_sz = strftime(&date_str[0], 99, "%a, %d %b %Y %H:%M:%S GMT", &my_tm);
                                date_str.resize(date_str_sz);
                            };
                            update_date_str();
                            get_cached_date_str_pool_[i] = [&]()->std::string
                            {
                                if (std::chrono::steady_clock::now() - last >= std::chrono::seconds(1))
                                {
                                    last = std::chrono::steady_clock::now();
                                    update_date_str();
                                }
                                return date_str;
                            };


                            detail::dumb_timer_queue timer_queue;
                            timer_queue_pool_[i] = &timer_queue;

                            timer_queue.set_io_service(*io_service_pool_[i]);
                            boost::asio::deadline_timer timer(*io_service_pool_[i]);
                            timer.expires_from_now(boost::posix_time::seconds(1));

                            std::function<void(const boost::system::error_code& ec)> handler;
                            handler = [&](const boost::system::error_code& ec){
                                if (ec)
                                    return;
                                timer_queue.process();
                                timer.expires_from_now(boost::posix_time::seconds(1));
                                timer.async_wait(handler);
                            };
                            timer.async_wait(handler);

                            init_count ++;
                            while(1)
                            {
                                try
                                {
                                    if (io_service_pool_[i]->run() == 0)
                                    {

                                        break;
                                    }
                                } catch(std::exception& e)
                                {
                                    if (crow::logger::get_current_log_level() <= crow::LogLevel::Error) crow::logger("ERROR   ", crow::LogLevel::Error) << "Worker Crash: An uncaught exception occurred: " << e.what();
                                }
                            }
                        }));

            if (tick_function_ && tick_interval_.count() > 0)
            {
                tick_timer_.expires_from_now(boost::posix_time::milliseconds(tick_interval_.count()));
                tick_timer_.async_wait([this](const boost::system::error_code& ec)
                        {
                            if (ec)
                                return;
                            on_tick();
                        });
            }

            if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << server_name_ << " server is running at " << bindaddr_ <<":" << port_
                          << " using " << concurrency_ << " threads";
            if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << "Call `app.loglevel(crow::LogLevel::Warning)` to hide Info level logs.";

            signals_.async_wait(
                [&](const boost::system::error_code& , int ){
                    stop();
                });

            while(concurrency_ != init_count)
                std::this_thread::yield();

            do_accept();

            std::thread([this]{
                io_service_.run();
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << "Exiting.";
            }).join();
        }

        void stop()
        {
            io_service_.stop();
            for(auto& io_service:io_service_pool_)
                io_service->stop();
        }

    private:
        asio::io_service& pick_io_service()
        {

            roundrobin_index_++;
            if (roundrobin_index_ >= io_service_pool_.size())
                roundrobin_index_ = 0;
            return *io_service_pool_[roundrobin_index_];
        }

        void do_accept()
        {
            asio::io_service& is = pick_io_service();
            auto p = new Connection<Adaptor, Handler, Middlewares...>(
                is, handler_, server_name_, middlewares_,
                get_cached_date_str_pool_[roundrobin_index_], *timer_queue_pool_[roundrobin_index_],
                adaptor_ctx_);
            acceptor_.async_accept(p->socket(),
                [this, p, &is](boost::system::error_code ec)
                {
                    if (!ec)
                    {
                        is.post([p]
                        {
                            p->start();
                        });
                    }
                    else
                    {
                        delete p;
                    }
                    do_accept();
                });
        }

    private:
        asio::io_service io_service_;
        std::vector<std::unique_ptr<asio::io_service>> io_service_pool_;
        std::vector<detail::dumb_timer_queue*> timer_queue_pool_;
        std::vector<std::function<std::string()>> get_cached_date_str_pool_;
        tcp::acceptor acceptor_;
        boost::asio::signal_set signals_;
        boost::asio::deadline_timer tick_timer_;

        Handler* handler_;
        uint16_t concurrency_{1};
        std::string server_name_ = "Crow/0.1";
        uint16_t port_;
        std::string bindaddr_;
        unsigned int roundrobin_index_{};

        std::chrono::milliseconds tick_interval_;
        std::function<void()> tick_function_;

        std::tuple<Middlewares...>* middlewares_;





        typename Adaptor::context* adaptor_ctx_;
    };
}


       











namespace crow
{



    template <typename ... Middlewares>
    class Crow
    {
    public:
        using self_t = Crow;
        using server_t = Server<Crow, SocketAdaptor, Middlewares...>;



        Crow()
        {
        }

  template <typename Adaptor>
        void handle_upgrade(const request& req, response& res, Adaptor&& adaptor)
        {
            router_.handle_upgrade(req, res, adaptor);
        }

        void handle(const request& req, response& res)
        {
            router_.handle(req, res);
        }

        DynamicRule& route_dynamic(std::string&& rule)
        {
            return router_.new_rule_dynamic(std::move(rule));
        }

        template <uint64_t Tag>
        auto route(std::string&& rule)
            -> typename std::result_of<decltype(&Router::new_rule_tagged<Tag>)(Router, std::string&&)>::type
        {
            return router_.new_rule_tagged<Tag>(std::move(rule));
        }

        self_t& port(std::uint16_t port)
        {
            port_ = port;
            return *this;
        }

        self_t& bindaddr(std::string bindaddr)
        {
            bindaddr_ = bindaddr;
            return *this;
        }

        self_t& multithreaded()
        {
            return concurrency(std::thread::hardware_concurrency());
        }

        self_t& concurrency(std::uint16_t concurrency)
        {
            if (concurrency < 1)
                concurrency = 1;
            concurrency_ = concurrency;
            return *this;
        }

        void validate()
        {
            router_.validate();
        }

        void notify_server_start()
        {
            std::unique_lock<std::mutex> lock(start_mutex_);
            server_started_ = true;
            cv_started_.notify_all();
        }

        void run()
        {
            validate();

            {
                server_ = std::move(std::unique_ptr<server_t>(new server_t(this, bindaddr_, port_, &middlewares_, concurrency_, nullptr)));
                server_->set_tick_function(tick_interval_, tick_function_);
                notify_server_start();
                server_->run();
            }
        }

        void stop()
        {







            {
                server_->stop();
            }
        }

        void debug_print()
        {
            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "Routing:";
            router_.debug_print();
        }

        self_t& loglevel(crow::LogLevel level)
        {
            crow::logger::setLogLevel(level);
            return *this;
        }

        template <typename T, typename ... Remain>
        self_t& ssl_file(T&&, Remain&&...)
        {

            static_assert(

                    std::is_base_of<T, void>::value,
                    "Define CROW_ENABLE_SSL to enable ssl support.");
            return *this;
        }

        template <typename T>
        self_t& ssl(T&&)
        {

            static_assert(

                    std::is_base_of<T, void>::value,
                    "Define CROW_ENABLE_SSL to enable ssl support.");
            return *this;
        }



        using context_t = detail::context<Middlewares...>;
        template <typename T>
        typename T::context& get_context(const request& req)
        {
            static_assert(black_magic::contains<T, Middlewares...>::value, "App doesn't have the specified middleware type.");
            auto& ctx = *reinterpret_cast<context_t*>(req.middleware_context);
            return ctx.template get<T>();
        }

        template <typename T>
        T& get_middleware()
        {
            return utility::get_element_by_type<T, Middlewares...>(middlewares_);
        }

        template <typename Duration, typename Func>
        self_t& tick(Duration d, Func f) {
            tick_interval_ = std::chrono::duration_cast<std::chrono::milliseconds>(d);
            tick_function_ = f;
            return *this;
        }

        void wait_for_server_start()
        {
            std::unique_lock<std::mutex> lock(start_mutex_);
            if (server_started_)
                return;
            cv_started_.wait(lock);
        }

    private:
        uint16_t port_ = 80;
        uint16_t concurrency_ = 1;
        std::string bindaddr_ = "0.0.0.0";
        Router router_;

        std::chrono::milliseconds tick_interval_;
        std::function<void()> tick_function_;

        std::tuple<Middlewares...> middlewares_;




        std::unique_ptr<server_t> server_;

        bool server_started_{false};
        std::condition_variable cv_started_;
        std::mutex start_mutex_;
    };
    template <typename ... Middlewares>
    using App = Crow<Middlewares...>;
    using SimpleApp = Crow<>;
}





int main(int argc, char *argv[]) {
    crow::SimpleApp app;

    app.route<crow::black_magic::get_parameter_tag("/""index.html")>("/""index.html")([](const crow::request & , crow::response &res) {
        res.add_header("Content-Type", "text/html; charset=UTF-8");
        res.add_header("ETag", "\"md5/3b0c2c10e5f8348513208ebd121e4d82\"");
        res.add_header("Last-Modified", "Sat, 22 Aug 2026 21:16:03 GMT");
        res.write(std::string(R"***(<!DOCTYPE html>
<html lang="en-us">
<head>
	<meta http-equiv="X-UA-Compatible" content="IE=Edge">
	<meta charset="UTF-8">
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>TaiLing.cc</title>
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
	<link rel="stylesheet" href="css/theme.css">
	<style>
.header {
	position: fixed;
	width: 100%;
	height: 100%;
	background-image: url(images/header/headerbg.jpg);
	background-size: 100% 100%;
}

p.console-fontsize {
	font-size: 20px;
}

@media screen and (max-width: 800px) {
	p.console-fontsize {
		font-size: 16px;
	}
}
	</style>
</head>
<body>
	<div class="header"></div>
	<div class="section type-1 big splash">
		<div class="container">
			<div class="splash-block" style="text-align: center;">
				<div class="centered" style="width: 90%; padding-top: 50px; padding-bottom: 50px;">
					<div class="container">
						<div>
							<h1>TaiLing.cc</h1>
							<p>is compiled from single C++ file,</p>
							<p>and produces the sourcecode itself.</p>
						</div>
						<div class="row">
							<div class="col-1"></div>
							<div class="col-10" style="background: #000; padding: 30px; font-family: monospace, consolas; color: #909090; text-align: left; overflow: auto; border: 5px solid #909090;">
								<p class="console-fontsize">$ curl <a class="path-to-cc" href="tailing.cc">http://tailing.cc/tailing.cc</a> -o tailing.cc</p>
								<p class="console-fontsize">$ sudo apt install libboost-system-dev</p>
								<p class="console-fontsize">$ g++ tailing.cc -std=c++11 -O2 -lpthread -lboost_system -orun</p>
								<p class="console-fontsize">$ rm tailing.cc <font color="#606060"># Take it easy, you can soon download it from localhost</font></p>
								<p class="console-fontsize">$ ./run 8888</p>
								<p class="console-fontsize">Then, you can browse <a href="http://localhost:8888/">http://localhost:8888/</a></p>
							</div>
						</div>
						<div style="padding-top: 20px;">
							<a href="http://tailing.cc/" class="btn btn-outline btn-lg">Homepage</a>
							&nbsp;
							<a href="https://github.com/yuantailing/tailing.cc" class="btn btn-outline btn-lg">Github</a>
						</div>
						<p style="font-size: 14px; padding-top: 20px;">&copy; <script>document.write((new Date()).getFullYear());</script> <a style="color: #fff;" href="https://github.com/yuantailing">Tailing Yuan</a></p>
					</div>
				</div>
			</div>
		</div>
	</div>
	<script>
/**/;(function() {
	'use strict';
	var pos = location.href.lastIndexOf('/');
	var path_to_cc = location.href.slice(0, pos + 1) + 'tailing.cc';
	var elems = document.getElementsByClassName('path-to-cc');
	for (var i = 0; i < elems.length; i++) {
		elems[i].textContent = path_to_cc;
	}
})();
	</script>
</body>
</html>
)***", 2992));
        res.end();
    });

    app.route<crow::black_magic::get_parameter_tag("/""")>("/""")([](const crow::request & , crow::response &res) {
        res.add_header("Content-Type", "text/html; charset=UTF-8");
        res.add_header("ETag", "\"md5/3b0c2c10e5f8348513208ebd121e4d82\"");
        res.add_header("Last-Modified", "Sat, 22 Aug 2026 21:16:03 GMT");
        res.write(std::string(R"***(<!DOCTYPE html>
<html lang="en-us">
<head>
	<meta http-equiv="X-UA-Compatible" content="IE=Edge">
	<meta charset="UTF-8">
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>TaiLing.cc</title>
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
	<link rel="stylesheet" href="css/theme.css">
	<style>
.header {
	position: fixed;
	width: 100%;
	height: 100%;
	background-image: url(images/header/headerbg.jpg);
	background-size: 100% 100%;
}

p.console-fontsize {
	font-size: 20px;
}

@media screen and (max-width: 800px) {
	p.console-fontsize {
		font-size: 16px;
	}
}
	</style>
</head>
<body>
	<div class="header"></div>
	<div class="section type-1 big splash">
		<div class="container">
			<div class="splash-block" style="text-align: center;">
				<div class="centered" style="width: 90%; padding-top: 50px; padding-bottom: 50px;">
					<div class="container">
						<div>
							<h1>TaiLing.cc</h1>
							<p>is compiled from single C++ file,</p>
							<p>and produces the sourcecode itself.</p>
						</div>
						<div class="row">
							<div class="col-1"></div>
							<div class="col-10" style="background: #000; padding: 30px; font-family: monospace, consolas; color: #909090; text-align: left; overflow: auto; border: 5px solid #909090;">
								<p class="console-fontsize">$ curl <a class="path-to-cc" href="tailing.cc">http://tailing.cc/tailing.cc</a> -o tailing.cc</p>
								<p class="console-fontsize">$ sudo apt install libboost-system-dev</p>
								<p class="console-fontsize">$ g++ tailing.cc -std=c++11 -O2 -lpthread -lboost_system -orun</p>
								<p class="console-fontsize">$ rm tailing.cc <font color="#606060"># Take it easy, you can soon download it from localhost</font></p>
								<p class="console-fontsize">$ ./run 8888</p>
								<p class="console-fontsize">Then, you can browse <a href="http://localhost:8888/">http://localhost:8888/</a></p>
							</div>
						</div>
						<div style="padding-top: 20px;">
							<a href="http://tailing.cc/" class="btn btn-outline btn-lg">Homepage</a>
							&nbsp;
							<a href="https://github.com/yuantailing/tailing.cc" class="btn btn-outline btn-lg">Github</a>
						</div>
						<p style="font-size: 14px; padding-top: 20px;">&copy; <script>document.write((new Date()).getFullYear());</script> <a style="color: #fff;" href="https://github.com/yuantailing">Tailing Yuan</a></p>
					</div>
				</div>
			</div>
		</div>
	</div>
	<script>
/**/;(function() {
	'use strict';
	var pos = location.href.lastIndexOf('/');
	var path_to_cc = location.href.slice(0, pos + 1) + 'tailing.cc';
	var elems = document.getElementsByClassName('path-to-cc');
	for (var i = 0; i < elems.length; i++) {
		elems[i].textContent = path_to_cc;
	}
})();
	</script>
</body>
</html>
)***", 2992));
        res.end();
    });

    app.route<crow::black_magic::get_parameter_tag("/""images/header/headerbg.jpg")>("/""images/header/headerbg.jpg")([](const crow::request & , crow::response &res) {
        res.add_header("Content-Type", "image/jpeg; charset=UTF-8");
        res.add_header("ETag", "\"md5/97dc221ad1c748626146af95ba098fad\"");
        res.add_header("Last-Modified", "Sat, 22 Aug 2026 21:16:03 GMT");
        res.write(std::string(R"***(ÿØÿà JFIF      ÿş ;CREATOR: gd-jpeg v1.0 (using IJG JPEG v62), quality = 95
ÿÛ C 			





	


ÿÛ C


















































ÿÀ 8€" ÿÄ           	
ÿÄ µ   } !1AQa"q2‘¡#B±ÁRÑğ$3br‚	
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyzƒ„…†‡ˆ‰Š’“”•–—˜™š¢£¤¥¦§¨©ª²³´µ¶·¸¹ºÂÃÄÅÆÇÈÉÊÒÓÔÕÖ×ØÙÚáâãäåæçèéêñòóôõö÷øùúÿÄ        	
ÿÄ µ  w !1AQaq"2B‘¡±Á	#3RğbrÑ
$4á%ñ&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz‚ƒ„…†‡ˆ‰Š’“”•–—˜™š¢£¤¥¦§¨©ª²³´µ¶·¸¹ºÂÃÄÅÆÇÈÉÊÒÓÔÕÖ×ØÙÚâãäåæçèéêòóôõö÷øùúÿÚ   ? õ–ryÍ0ÈG8ıj)%¡üª6‘#5şvÆ™ş2ûNeÿ jšÒœsP†c×ùÑÒµŒ5-QcÚ^0ô¦3úšk68šÎ{šÑDÑP$Ñ¿JL÷ÍG½}iàV±Š+êìsKøS^BO˜I!#8+úÖª#TıíMg÷Í0ã° ät­#Õ¼çŠ7·­F]³IZ(š*DŞgµ4Ë×š`Ç¦iNp)***""\r" R"***(iÜ¯b‡ dšo™íLç¯Z2ßİıkU½ˆ­!'ši˜ãšS¸ŒcFÇñZÅCÄ™íJ²ãÚ¡ IÆhÜİÍl¢Uc&{æš\öâ£.qéM2œõ5¢…ªİØœfšd#©¦jBIêkEıŠe'ŠO3Ú˜X
nòzÑD¯dI¹½h,Şµ›şÕ4¾{Vª(¥I²GõNi77­%j’FŠ’BîcŞšÌGoÆ”ä)***""\r" R"***(5”Iª[–©¡¤“Ö“Üâ†8ïÂš	 Ö©*k¨nnæ‚ÙíIAëZ$Z¦‚˜ızÒ•áZkqŠÒ)”¨ˆÍÎ	éÚšX((sÀ¦±ÛÚº"U!i`´İíëM/ÏÖÑF‘¦<H@À¦4„õ4Òõ£czV±‰¢§qLœt¦NM)Vš@	8¤R-SaLcóSÊ2ÔÓñ­bihŒE-#.îô W ÍZFŠšHì1LrAÆ{RòAÊş¦•=—õ­–ÅªlJ(9¦[&®%¨0$’)»ÛÖ•—9¦0Ü1[Å¨{Š<Ïj‰F‡?>¶Š-Bãš@GçLgb	#>8ÒIëZ$‘ª¦(?6ãCÉÇJJG$+E±\ˆa99¢´„Ğâ©\®FÁ›oj@ãÑåûÒ2ã íV·*0Ô“Q¹$‘=)ÌÛN1M$±ÇcÚµQ5å'Í4©=[ô©w?•4ğN*Ö…(‘‘ƒŠ(n§ëEhŠå¸°û¿­#6M9ºe4ËQ£4gµ+ıÓL«M$+ÉÇJŒ)***""\r" R"***(Ç­?gµI¢ÔF0  M%=—wzP tI³E¡ 8Ç$gµJëHíQ6îİ1ZÅ¶Z‚I»æÛŠZ+X¦_(QL`A$ô•²RJ:R/Aô¥­j(iJi$õ§Hp3Q—ÈÆ*ÕÍ}¹ştß3qÆê)nÍj·)@ZG$ƒIåûÒ2íïZ äw‘›b—¥5Á' v­c¹j#i¥ğqŠu4¦NsZ¦Ë³NNh¥ îÚ( MkBQK¹½i+E;”bî+øÒ1$Õ!éQ°=)***""\r" R"***(m$G“œæ”±<JPÁÍ78Åh¤Ù|¡M~Ÿ?iÚ8ç½Ò¶Å¤ìEEJT¢˜à‚´‹H¥6˜ı
yuŒ»s[E¢â¬2ŠRŒN=iB95f‰\mFİOÖ¤*WéšFŒôªLÖ6E;`Å&Æô­“ÔÛq	ÀÍ4’TœS¨­)***""\r" R"***(aª:¿iÔP=)***""\r" R"***(1ˆÓñ¦‘€zÓûâ€¤œM;Æ$`qƒGzw—Ï_Òÿ ¥Z’; †2î9Í Ny5*£¦¿Ş4ù™ÑG·-K³Ş#9¥ûÕ¦o¢?/œçô¥^ƒéO;šB»pZw7…Ä¤n‡éNØpsFÖâªçT6"'ï/ŞŸ°ã#ò !>Ôs£x¡»~]¹¡WiÎjE'Ö‘£ ñG:: †ÑJTã…ıh¼Ôs&t@NôSÕv´´“:#¡3ÚŸtS€ÉÅ9PçƒCfğdc§ãKRlÚÄÓTÄ‘Jèë‚RS|¿zxRFj”‘Ò–¢QíN
GUıiÄÓçFñ½ÈÈ àĞsRícÚ”FM
gLH dŠruü*O/ßô¥UÇ9§ÎÍãa”õ'4å]İèÙÔçµR•Íàìô›ÿ -)ÔSæ:#¨Q“´ä\sN ã>½é©jtE)***""\r" R"***(UÇ9íN§"ãœÓª”µ7Š°P	 ÓÂíÍ$Îˆ\eóíHP1ÎjÓ¹ÑDO½O¤XÎr)qÎ)1İÚ‚	•—wz¸tÉƒÚ•	#$Ò€HÎ(^¢ô:¢Â„àÒÉÎiÈ½4ù¥r)9ëNØ1×ñ¥TÁëTtB@‘NSÁÔ‚=½_zzÆyÅP‘ÉÈö¦àç¥hÈ4Öuê“: ì4&sJà‘À¥ z
£x²=»1Ò€vR{Rwü)İc9çæ•—wzR›†qM=N˜=Hé®¿Ä*UF3MprN8õ«NÇT]Æ®@æ”R…$ô¥ã¿éTÍâÆÓ× úR¨$`Q³ojw6ŒµOQíCõü(1ã'=¨ ¯ ÕEQcKrjnv÷©#­GL$Èğs¶Š—a 0ü©=¨:£-À'¥9;Ó»âŠ´kR”"“¥_1Ò¤8Ïjr7ğĞ£'q4ğ›€9«½Ñ¬d7v#ñ¡G;ëN+‘Buü)£¢2aó(Ï­;vàx¡z¥-lt)1¥øÆ)¦œë})¦šW:"õ
F;FqA¥å@#4ÕˆHk´J:
?Ò–­ntBVaF{P=(Œõ<Sº:¡!1éE)C(HçŠZ˜ƒšPüdŠP6€)qŸZ±´f4/;ƒuö§ch ’)Á23šÒ-Ælh,8­	á½)ê¸¥ µI™ŒŸºxô£g?)©iÈÅRgDfÆÍğ¹:Òl¹ªæGD*1¤ç=)Ä•êsJ">œSÖCI´uÂ Şh©'°Å4ÄGZkc¢5ç4äoáÅ'”:çñÅ/–O¦tBwxÎ¥¸¤S‚p8¦¬tÆh@{ŠE"#b#=hˆLõ§by¨İÎ3NrOzÿ ÿ ,ãËÊ¢*¿½)—Œf£¤v­T)***""\r" R"***(#Dy“ĞSds R3 8"šX‘ŠµEEæ{S]ÁêqI»ı“ùS\ç’+XÓ¥qÛ‡÷5¤ ã==©…È<*BI95¢¦5G]‡ù™çu4Êı¦Ò7Nÿ …kX¥Dvöõ£{zÓ?ïª]ßìŸÊ­E”¨®¤…èj7lõl})i}HªŒJTR€H9…€àBäq[(RYSLv\c4…ØŠc6#ó«ŒK02Ú3Ú›El£cEI.Ş˜¦­)'Öšçœ`t­TM1¶x¤/êEàgŸÂšÙ?ÃúV±J’'4yß­&Ö¨ÔÑD¥Nİ$´}h£šÑD¯dÁ‰äûSœgw´¯œñ”ÃÓüjÔKTÅŞ¨'M3ø¿Â—óÿ U(–©yy'šk+cåJzÒcØş5¬S)R`N;~T…Ò½©JÜıkEXÒCw0àÓz¥=ÒQZÅ*CëMp[ó§”$ñŠiu­¢µ+Ù‘‘ƒŠayÇéR7áøR`‚µÊT˜İÄ#y9§í#¢Ò0p+x– 2‚{šltüé¥XòMZZš*`_œÎšY”©&’¶Åªwœu8¤ùA­8€zÑT•Ë!¥H·4ÂÀq}*GV¨Ù}¹­"£)***""\r" R"***(Ü§ïi`ü¿Ê—czÑåæµJÅû194Â¬{Š“aìi½+x”©à  Ó©6ûšÑ3EMŒ'4S™O^?
mY¢¦ÃÒ‘²–ƒ»šm²¹ñÏJFRİ)Ì¤ri+E¸{1£)Û9¤bIéŠy õÖRNEh·-@ÉÎ8éM©@<M(IÈÅjš)@nO­—aõ˜Çî‹PĞS	ÍIM(O¥Re()***""\r" R"***(éÍ!rOËÍ8£Rc±Z%r”F•8Ëiµ%#(Ç©#XÅèh¥Ú})0GQZ$h¡Ø(¢Š´™q€×#89¦Ô›uı)0=i¡§"!`Û¸ZN‡‘úT­÷©0=+x‚‚#ÇlSJdç5!C1MéZ¦‹äC¨Í.òGOäg›PùrNM#·¥;a¤*qÈ­§-ˆé	#*FPF Ò¤šÑ;–£¡6F1INqÇ›ƒèkD5 ¤fÚqŠ\CK°Ãñ­b5"A9T…@8 SY	9«)Bãp3œSKsÊñR9äÓJöÇz¨¶5LŒœœÑOÀô¤}kH” 6‚ê)şX=3Hc#§ëZÅ”¢1€ÛÒ™RùgÚÇ’kR‰ı ö¤qÂşB¶LÑ"9;Sj@»)|¯aZ&W)ê?Jk/<
œÆq“ŠaBO¬dZ…Èqê(êx/—ô¤*Æh™j™qL%‰ÇaéR”$ç4Y1T¤j C’{
P=I³ıŸÒ”G´r?*ÕI%Ø‡h#¥4©3G»±Ò‡8¢•¢®4(
P è)Á äÓ€ôÔ ˆ°:àR)æ,ö4‚<u«æ: †àzRa};aõ§<|ö§ÌtÃB<
M¸ê:Ô¥=3HW¹_Ò©;1Hb”‡©©A<C.N=é§©¼u#¢°g“Iåæ´LŞ	‰@8©[yë@OöJ«1³F)Tr)åp¸£aÇ^j[: 7 t`zS‚òi
Ò¤è‰€qÅ* s‘OØXò?:rÆGJ})***""\r" R"***(âĞÍ£Ò u_Ò¥òOu•)ŒÇëG1Ñ…ÏAO
<GhòzÊcx¤6š'(‡#"”CßùÓæV:c¡ §¢ğxëO“ØS–"OÒÑÑ)***""\r" R"***(H‚zÓ¶ç¢ş•&ÏöJ_/ü)s1#Qó`ÎŸ€:
6çü)Â3Ôô¦™Ñ˜‚ŒJ—Ÿ»NöÇæ)ÜÚ;‘€;
yQ”ï/”ò€u©3xÌx?wô£gû?¥Oè(ÀôwgLHÕF9¸éRã—ÊöÓ:`E@$t§ù^Æœ"ã ª¹Ó
[¥8Œ”"š\¸¡3xŞäxíŠU6§àg8£9ÅW1ÑÃ t`uÅ']ŒzSLé€”ä ç"•c`y¥8D{M;Åˆ\
B¼d
”!^€Ñ·©3xHj G"é@^qŠpB46o!3JªAæŒ”å^æ—37‹Ó­Ié@]Ş”å\uÅRw:!+¾s€3Ldbq*Á_Uı)
ğkNnÇTdWÙ´äJ,¹ÅJÑŞÔYÎ{S:c" 	â”GÎI©Yû½hòÈûÂšÜèŒìF«¸§‚¤hñÛò¾WâªúP’d9àv¤XTÍA>•q:!$0(
0=H#9ÈäPÑµGLZhf è(àõğ£H©ÇLÕ#h»14Œ½I´áı(*{¯éZ$˜½60ãŞ”)#¥JËÆ1I³åÆ9ª6ƒcpAMqÇ¥	ò¤ÙÏ4p‘\œSğ=<DGcNX½¿:¤ìtE¡Š»»Ò àRùDzPP÷Zµ#u"*z}Úp=‡â(òÏµRÜÖ2BS|²~íHJP?ÈªNÆñˆÀÀ¥Î*M¹ä¯éG’y=j”®tFddzÓZ<ô©™ê(Àì+NdoÀÆ.Ü Àb¤Ú?»úRªdqŠ9ã")***""\r" R"***(ƒ=i
‘È©ŒdzRylzSRGL$7Ò•T”ñ^?:_(j®dtA¢2
š–'ô©<¿\P##¦)İÁ€v•üiØ”áy#šMÚ©4m
ˆŒ)¿
u;Ëlğ>´àœ}ßÒîtFB*‘×ğ¡=)***""\r" R"***(<GëúR´l?®)¦m	´ÈŠ`ğh(G"¤1Ò'•ıj®Î¨TD`òâœc¥?ÊöçéJ±°<Ši
C0qœS“=ÇéOUÉÁœ·QùS¹¬j–#µ!99"¥ò¸änÂ:
¤tB Ñƒü¥g\˜¥
M^ÇT&! õ p)vZP0(:cSAÔbœ:FÜöÍ*¡cÇëV­cxÔ¹êlÇ“ŸÖ˜\çµ!f#­4»Šÿ /ãşgU!YÎ0sùÓœu¤v4ÃëŠÑE*W)3wÅ5—ç½0îşZÆ	Q±0“Ä?:F—#ü*-Ä}áMg=³Z(”¨y‘ÎxİÇüšBİÍ4°=ÍkŠT.?q¤2œÓ3şÑ¥UR3ŠÑE£aŞgùÍo·ëL(sÀ¤ªäEªW%óµ1¤œş4››Ö˜û›œšµÇìE2Òo>‚˜rÊ?ZBÄsŸÂµŒQD`Æi¯&Gn´Âå†1LgŒâ´TÍ#DÉÇçĞTA¯ëFò+UZ¤É±áLiqHXôÆSü+Ú­GBÕó	î(ûŠ‹OÆŒŸJÖ1Eª*Ä†nx4yÇŞ¢8ÿ &”cÖŠ%*^Cò=iúšnsü8 œVŠ%*"äôÖéHÒc ¦™xè+Eö(PJŸ…#J~èÓ<Æ=¨ÉÆNMR‰Jn”o`}i?Â)…›=kEh©yéG˜{ö¨·SHÎÃ¡ıjÔF©Ø‘¤QÉ4Æ•sÅFI=M¢‰ª§rPäŒŠFSQäôRkXÄ¥LRrzP	)***""\r" R"***(&í½é2=Ej‘J›'ÖšìE:˜ÊÇ­kR¦Ö“ß4İÆœPcÍ4©‘úÖ‰"ÔwäûR1=‡çK1Mp ÿ ëÖª%Æš!Î¥)***""\r" R"***(€Ó4„şui¡aìøëL9<“CdpFx¤%»
Ö(Ò0° â”ŒÔgp=iKàµjµ/Ù¶+68ÂÀsŸÊ—põüé>_jÕ-)***""\r" R"***(cI	¼zQæJMéFÖô­FŠ \1IEZ ~'ó¢ç
¨—ìĞŒÃ4ÜŸîÒ°aÉÜŸCZØ\‚şR{Î€*(;ˆøÏNÔÚsõéÚ›UcHÓl)ŒiôÒ¤­"¹ÑFH4U¨”©°¦±NüÓºÒl_J´?f0ã°Å#Š¯ÊBŠc!Ç"´H¥3yô¤b[ƒRmc›Ò´HÖ1€Í;búP‚–¬«1®Øâ˜wtQOuİùSpGZ¤W)Îy¢œÊÅ²*¨‘Íj™J)6©äŠs!$œ~´›qëùÖ‹bÔ qHAÈ´UBÃ i­÷O÷RNiŒ	
Ö,ÑDgĞQ×Š]éK³Ş­H¥7P›R2qÈ¦²gîÖ´RCh£Ë>‡ó ‚§ıkH»•ÊÄ*QFÅô£'ĞÒç€*Ó°r1¬ 8¤ ´íŒO4laV¤Zˆİ‹éFÅô¥¥
Ägi•Ê7AÀ£h=E;aÁ'ŠB@ïT¤5¬ âš@#ß0À?­7czVªCQcB¨9‘À8ïOeÂçÓHİíZÅ²”HÀ ä
ZR„tæœ±fµR4ŒF’HÅ7júT‡?…7czV‘’6QĞ†)***""\r" R"***(4¨'8©HÈÁ¦9ùGjW)!»Ò˜G$`õõ©v63úSvàô­Sv.(hÙ»MÉô©6/¥ñŠÚ&ª(f1I±})â>zÓŒXşÖ´½‘¬Uˆ¶/¥(\O	Àò˜ Í$Ú5Š¹)***""\r" R"***(&Ñ»51M¼æ›µ}*”ÍàˆÂ¨9”€zŠs'÷EúÓæ»: ˆœ x¤##¤eÁÉÓY2r+U#¢))***""\r" R"***( /AF9Í(ChØÂŸ6¦ğ,r)v(9Å< “JTÏ5WgL 9í‹éNGE !Ï"®èèŠ²±}(Ø¾•!QƒMsÈ©æf±µ}(Ø¾•&Åô¤(1òŠjGLƒ0Oš“búRªÃµ.Öô§})***""\r" R"***(”F	Á¥U ô§*waJsÀ©¾†ñĞk&HÀ¥1ó
q84õ ¯#ô©:"F{Š6¯¥H FÕ=¨M˜R… ¥éJª9§sªiAÜQµG8§ílóüèe d
®mˆŒØ¾”  0»XóJ‚3BfÑ»‚W «=©ŞY bªö7Š´‚•¶‚œûÂ”(ã­4Ú:!r&Œ‘B¨Ç"¥ HPcV¤uAÜ` t´»3ßÒ•TÈæÎ¨¡B©)¹OJJ`CŞ©3X €)¬pvÖœ=)Dg9"­ltÂö#ÚGQNÚ¾•'–1œ~´yîâÆ SÂĞRˆÆrëNT9ù…3X±y§ AK³o u§*xQs¢,3ĞSvíã'Z
àò*”–£
JUA˜sO
OAN1È¡HŞ	¢=£Å9 'íNØ¾”Š¤1â¨êˆ ĞTTr7kÔğ	éMntGa3ÔÊ™Ó9Ç¥DPŠ¤îo&& à
qFÏÉ5FñcBĞS™FĞiJ=(
s†vªº:"Ä@r)NË¥( t¦2y"‹Üè„ˆÊöaIµqŒT…rwv£bã¥Zg\;ŒE €0"Ÿ³wj6©äµW:`Èü°†€ è*^”yYçjFêCU:îJk*]éHA´LÚi‘2†¦… ô¥e$
n3Æ*®tF¥Æ•§üiáCJ©ƒÈâ©3xÌnÒ S”ê)I
0E!CüëM˜1ƒM8ÏÊ)ì¹æ‘PcæQÜèOA½úP)***""\r" R"***(?
29¦”çåUÜÚ,CÍ8m<b•Tc‘NXûO˜ÙHAOÀPH¤@SÕCšiÜŞ.ãNr?o—Ÿ˜
‚)***""\r" R"***(àf©6tFV"*	É Ó¥<€Ãp^ig=1V™Ñ‰Ö(8'8£aÍ;*ƒÔS˜ŒàŠM¬:R…úSI¦o	vÛAàqíNP¤g¾^ëOUãæGLet4  ¢Ÿ±}(ÀÆ1ÅRÜÕH`]Æ”)î´à r(8ì)›Fl@00(Ï¯&À†‚ ö¦™¼*22 ó}h
:‘Ï­=Pgßµ8ÇÜŠ¤ÎˆÎÃ
ñ“ÓÚ#væ¤U8àS•~aNçDj4F«ê´ ĞT…AãÁè)›F Ìb˜FNZ˜ÇÔÒ„æ­3hÔ" ‚2)PäŠ~ÒÃ§¢2£ S:aPn¥&Áœš~Â¿¥(CŞ­ltÆ À è)è¤‘ô !?ÃO ”îtFg¡´ ñI½}j6b)***""\r" R"***(4¹>µşfró‚¨yùß­#IÇ ~5!8õªP/Ø/!$tİÇ8$ŠG#Íh ?`Û»R@àQ‘ïùS[“À5¢J„.~”oû_¥…”Z(–¨¡Êç<)wú
m#6ŞÕqˆ½—aşgµ0º÷4Òçµ4’{“Z(ìIr=i¬àqMÃwZJÚ0±CKàñMf8äÒç €G5ƒœóZÆ(q¢8¸ìi¥ò1ŠJ+^UcEI$t¤^(qÔ™ò)Æ#T¥ò8¦—'§6GŞı)3šÖ0)R{P³Ö“€2M1ˆ$Õªe*i.3Í×Ö˜z]ç­yT…/Ô	6ƒÀªQ4Tn$LæŠMÀôæµI©ÙŞŞ´ŒÄy¦’ùà~”ŒXsùU¨¡û1K€SL™à·éH@=Iü©¬¿İÏåZ(Ø¥M.Ni¬Ù"ŒCMdÉæ­%r¹o_ZPAéLeÁàãi)***""\r" R"***(A"‚À:fâyÜ(9ê}ê’4TÅó=¨ó?Ùıi±=1K°w5¢Er½}JBüŠ6ZB‡µHjÆ#¼ıi­'biÅ fšÊHéZD¥I)***""\r" R"***(ó=©äc#šLæµHÑRH)ÈÀu¦ÑV‘^Í-ÇÊ;S	'’hf'ò¦¸ç¡éZ¤Z§tø~t„ç¨çÖ“ÔNZF±¦QÒŠÕ#U¢îşKô«H¥
Œp)¥H"”³v±=jÒe¨	Ev¤`HÀ­)SÄ“ŠJ
·LU\A­…„ cŠqE´>IÈIa-ØS[9ç­8°M5ˆ'ŠÒÃPw‘·cå¥Á=¨Áô5I©ŒÚÇµ%Iƒèi¡­QJA ?h â™ƒéZ¥qò& p3LflàşTò21MØ=MRVf[€ZiÎy§2`qšiÜU#HÀ(¢Š²ùIæŠ ' £ĞÕ­‡a÷*¨#$SˆÏP+E±\¤g©¨Û©úÔ¤)¡@9­ÃQwµjp t´ OAT‹Qà“;SsÎjg\J‹Ò­\ÑAØŞ”@ä~4ı­éC.G9¦®>WĞŒ€zÒm\ãıƒÔÒ2ckDõFà‚ŒŒyBİA¤d#ÿ ¯[E¤ZˆÍ‹éM(wp8§íoÊ§ĞÕó*w³È§æ—ĞÑO™Éa6/¥Ò–ŒJ¨É(…TÅFT’*R¤”İƒÔÕ¦56Q´íÒloJ” ŒÒ$àƒZÆEr‘G&€zÔÌ˜S3×ùÖ±‘J$b0z
zÆ«B§š^{ñUvZˆŒœğ)v"Ai
‚rkX³E”;ºqõ§×õ§ìÖÂœVªLµ6 ği6/¥I°y¦+H¶ÊQ" ´å ƒR„fƒÖ·‹+”‹czQ´…Éâ¤Ø{Ò” qšÓ™šE“Å)\($sRm8Í!Bx Ó¹¼Q õ¤*ÁíOdÇLÒ#üiİˆİ«ØRQF¡¥(ÂÍâ¬ÈÜ qÔİ«éR‘ØÒmÅ4Îˆ¢=«é@ŒÀıj@ ¢”&:Z¦t@‹bç¥<"àqKåóœqS€E;êtGQ ĞQµ})ê„‚H¤Ú}*“7ŠÊ $
E œ{!Æ)***""\r" R"***(
£…¦Ù¼P@è(Ø¹Î)ì€t FzµMÍâØˆ õíNØ½@¥DÅ;`õ4ï¡¼Du `
@¼p*LgŠUŒÍ;¤tEˆşl‘øÓ‚ôâ‡8¡zMˆÍ‹éMØ}*M‡<p‹†¦úE2=‹éOvb—Êàpiê…³iÜê‚TcLd;NáÅM°zš
 8Í4ìt"5EÛÒ•T€)á9§,xè(LÚ#
‘ÔRSÙsÁ¥Á¥]õ7âSÁmÀ¥Á=.ÓŒÑvu@nÅô£júS¶¶zRG´LŞ;‰µqŒPqÈ¥Á8À¥Úq)İPcv¯¥ ĞSÂsš6SV™ªvFGE§l_Jz¦zşy«R:"ÄE àSö/¥*ÇƒĞÓ¶SM3hì1T ¥1ÕiÁB‘Šs.G9£¡¬XÒœ)***""\r" R"***(¢…Oï
p £)***""\r" R"***(éNìŞM«éAPNH§”ÇCBÆHÉšgLÕ\”S‚r)Á
ğ§,yêÓ#)qŸjQ?ÃúÔ¾Y#n)***""\r" R"***(2@4îÍc"1Çğ è)LE€$ÓÄMÜSLèŒ†RäŠ‘“'œĞ#ÛÎãZ]Å±Š‹¸qOØ¾”mİKI»³¢R åÕSEMå†=è1c±«:"ÈÄ`ò¢°úTŠ¹ëC!€i'©¼Y C1Å<‚84$Ö‰¦uBD~”Söq·”)4îÎ¨=¶ƒÔRãTª¹<Š
‘ïô­"ÍÈ†;ŠFºÔ¦.Â‚„œàÖ©ØÙ=H
qÛÖÇ‚N?°T«úS
ØÅRw7Œ†R3Š?º*O-±šBëùU&¬uFJÃy ĞRá»ƒFÖì)***""\r" R"***(4ÍT€âšPg#ò©
zR$U¦ˆNÃ \àŒ­8 8'‚)U1ÁÍRi›©ÜnĞy"…Ü)***""\r" R"***(?`õ4ôO\ãW6Œˆ‚ÈjEOAßšr®~ğ§+ØĞ™Ó	’0zÕFó«H¦²îèy«LèR!*Aö¥
ıœf,“V™´$7búR„`
RŒ)PyIêtÆHhŒƒëN1ÓÓ¥<)n†”G›‘´f0(=Wõ¤)GåRìÅ@i&o²0 ãŸ­0E?Ê'·¾W 5WGDer,7qšUŒ0û¿­J# äN1É5ièk #9ó9ëOÚOAO:óG26S±Æô¥({š“Ë§tk„AyÁZ
ÿ ²G½Kåc“G–LÕ&m¬ˆ y¥ ‚¤+ÆúPtîÍãUŒÀ¦”î?*˜F@#šS:SLŞ"ÚØÎ9ô§*ÉÔ‚<ôÍW±­ĞéŒÈÊƒÉ¡{Ry|cSœfÑ›#	è)è¸ê9§ˆ™¹á}i¶tÂgd]HàT~`ô4ŒXI¦±ãıküÚP?ç™Q$Ş=)***""\r" R"***('˜;
ˆ9?Â®4îÈ{7ÈSK)ê)***""\r" R"***(FÒ1Í b;ÖŠ™j‰.äşïéFõZyôÖf=1T Ä‘œ1ÎGçM,½Æj2Ì½@¤.z“T©P$2 p!`Nr*"Xò£v:ŠÕ@¥D“+ê)AÇ`j-ãĞÑæûšÑ@^Å“ùœÂ£2ıÓM.?½úÓ7“ĞV±¦5E²BÜt•0¸#Sûş´Ìæ­S-Q$.1)7àÓ8•5Ÿ#¸5¢j‰!Ô	yè)***""\r" R"***(C’zÑÈèkHÓ)Pò'2¯^”ÂÀœäS7d|ß¥4¶;Õ@¥BäŒÀvÍ&äşïéLŞ=)***""\r" R"***(Ç¡«Q)PdÇ§ãL.3LfÏ|}M'ÌyªQ)Qd›Ç¡£z¾êÛqÖ”1Çj¾RÕå”ŒmíéHH4İçĞR$`ÕòÙæCC0#¦“ŠipG«ŠFã‰ÀÍ4¿ ¦–õ4…”w­TCØê)çø:c6zf1qŠ)QN{S]T·#ñ4o>‚±=êÔR)S6ãœPXÆ˜)***""\r" R"***(“NÈÖ4“¼z7CP{nüh@ÅZ‰^Åî¢¸ì* äúP\tÁ­TAR°âã¡Å4¸ÇJnsÍµ¢jŸp'<`Rƒµ€ïLcÎpkDŠTî+= ã°¨Ë“B³væ­+CÎP)´ûÒ±ìß¥6µHÕS°˜”àê:ÒS[®@&´HµLyqÔøÒuæš#æü©À`b´JÆŠUb)wJm(SÉ«Hµ=9¦FiäqÍ5ùBãğ­"5Lnïc@—)¦ì¦­&>D.G¨£ƒŞ“`õ4à éVùSÔÖ$|¡iÔŒO@*’hjmÓ¥7wû#ò§œãŠaÜNHı+Dh Èì(Ş}&¡£ĞÓ²+‘¼ú
LCF¡§p1·ô¦„à ä©¤n‡œK´ÃĞâ­6%œ÷¢ƒÔÒÎJÑ\ÓRp3Mf&”äGåHßîÕ$5)T)êi '¥*®zæ¬¾Aßw &“{zR“ÄÓ’yâ´€“š(¢šmìÂ›°I4ê+DÁ@nÅ÷¥Çjx@Fy¥ÿ ^©2ÔlF@§jeK Çµ0 Š«Üµ ı(ÁE#çzÕ¢¹`€õü©¼gŠ\7¡¤Áô5I¤W(P@=hÁô4ª¹ëš¥ å#e àR`ú•€’­6RÆªdsG””ê*“±j$eTbŠ\İ)ŸOÒ´M¢˜Sv©ö§í$?:CÕ¬KPÈ Í6œOPÃò¦œgŠÒ,\¬ ò3AÁ=(¢´EÆ(nÅ'9¥Ø)pŞ‡ò£ĞÖ‰•Ë ›°zšxR{RV«a¤1†)¦=Ç<ş!@Ni@ÀÅ_5‘iÂœıßÒ§*)***""\r" R"***(&Áêjã2­b0ƒ¡@§ì¦‚€ó]’HfÕÎqHÊ:Ó°})OÆ©3H¤'–=M1riÔw7KR"ŠñŞƒ4­ÔÑ‚z
µ±Ó $jzŠ5Î)ê¥zĞS<‘KšÌÖ(…“§,jFH©yéÅ
€Çµh¤o†,j½©J)§ùc¶iL|ci§ÌtD‹`õ4»¤Z
ƒíG9´P›yÅ5ãPx©0})***""\r" R"***(#('“V¤t@ˆÆ1Å0?úÕ(P?úô…4ùˆ¿Ö‚ëRlZk Œš9˜¡U6Ş„=;S°})***""\r" R"***(ÍÄ^ÂŠqOJAæŸ1Ñ Tf€óJ=P’i9ÔEHÎ)vSNŒJ.’()â5©UF3Š\CLÒ7Lã\ğ)»©©¶’GçHPi³¢2"òÇ©§tà
R§8ù°j‘Óq¥9¡“=A§ì¦—4ï©Ñ¢ƒš_,zÒªíïJAERgD°zšFAœbóg¶(ØIİÍZiÇqcñ@A¦œCz6œd
³¢nÁêiv-(ÀëNÍ]Õã¸¡@§˜Ôr(Ø=i[¡úS: ´}¨ ñER5ˆS‡ÍòÔÜÂœ€ƒÈ¡»3XŠ)âœª­!SœàşTäg"•ÙĞ¶hÆ1Jª£Ò•T“O˜Ö,]ƒÔÓ‘ =M c¿çJsU{›Å‹åSJ
Z*™¼GĞŒâœ‘©Îi úSĞœŠW5[)***""\r" R"***(’!ØS
ãƒS†£cÂ©HŞ2±ÏöJPƒ¦9§ ä~Tı™õ\Æñ™Üv¢¥ØIÁ4 GçUtÍã!TôÍ)PhUÛŞ–©ntBCJ¡8<RÅ+[42œæ¬ê‹¸Ğ·4ƒŠp@G9¥Ø1Ö­XŞ2°Í)P@µ(àbŠÑlnÄ
jBŠ9Í;ĞĞÙ çÒ´‰¼XÂª(c‚(¥Pwt¦od
8¦•SÚı?mZØÚ-Ø(Øzqu`úgD¬Š ¦•SÚ¤)¸Ñå{féèEåZUŒÄÔ› 9¥UãT¤k2,sĞR÷§:´ã“ZEÀ*‘ià~í B½§«Ôb¨èŒ†²€r7hÎqRÓY@çÓ±¼f3hô•8Í­!¸§s¢2¢»B <J˜Ï|Ó©¦mj4F äSÂ«ŒH{SÂ•éÏÖ­;›ÆCYUN1ÅA=	¸rA ËĞqToØ®?
RŠisEÑ˜ ¥;Š\CNUÎ)¦mŠ¨3ÁüèdÇU§…œP¢©;šF©ÁœÒ€¹ç&9¤Ú;MnkƒY@˜\p9§…´l­Æla¢œ"—n:~F•W)›Â¥ÄÀì5‘G¥HàñùĞH«[™
8 Ó€^Ø§4}ñšO+ŒÓ6F7
[)  ıßÒ´£ó§„\
w±¼jØjØ~TõèFÑéNUÖ“™¼kk2‘Óñ¦îZFe#¯ó©A#ü
ö"– u¤.ã4Òp:ÓYÆ8&­D=ˆâqÉ¦ùƒ°¦œ‘‚iSúÕò‡±æ{R'¯İÊ;ÓY³ĞÕ(2•äúšBËÓ­FÍ·µ4±5¬i”©ïôÆ÷‡Ò£mäğM0õæ´TÒ-RDŞhşğ£¿éPŒwÏFªQ²ò&Ş;ŠF“•ãê:MÄ÷­T¨¤?x£xô4ÃŒri„œğÆ­Aì‰YÁf›Qä÷4«·?5R…†©È=)***""\r" R"***(¡¦îQ÷E
Ê;b­GCEG¸æp?úÕ±=)***""\r" R"***(+yÖ8ã­j¢W±¾:š€ñškuÈ_Öš[Î«•°dŒê:ş´Ó0úS7Ş›–şïëT¢Z£Ü“q?Ä?3î)***""\r" R"***(G–şïëKZrØ¡ä€8"š\âœšk2‘ŒÕ$?cqÅøûß­!qŒL¢´H!K1IEH¯bÔÑ‘ØÑEh½dzŠBàZF`8ÅZM‡²lƒ=?:ŒÓ3À¤ÜSúSäÔ¥E¡æCØSF;ŠMëëI¿Ú®)–©¤?w°¤$õÍ1ƒ¢‚ÿ :Ú)©Ü]ã›½…%kBÕ+
N{
kğ:ÒÑWªHŒ)D˜¥p2qLÇùÍZCT‡1ù Ïz1ÆqJpëWÕ;)***""\r" R"***($t&”cµ`â€	8ªEò…{QZ¤‹PBîİo$v¤£i<úS¦†³cŠiç­=º¥3ÚµV/”(ÈM.Æô¤d8ù…P(	‘ê(Èõl_J6/¥RÜ~Ì\ƒĞÒ1â€ è(*­XÕ;¦³qO(E0®âNj’W*ÌMçĞQ¼ú
_/ŞšF)Ù˜»Ï ¥ó=©´}h²VÇo”ÃĞı)ÃŸ­#`ğ*â\i‘ÑKåz5(AMkÜÒ0Ü1š íIåûÖ‹a¨X`ÂŠ2=iásK±}*“ErŒæšS'$Ô ĞS_¯áTËQ"#SÊƒÏz@ƒ<šcåøQOØ¾”l_J¤ÃÙ@Å>“búRÓNãä°Ö\òM7Õ!b˜S9­Å()***""\r" R"***(##¤«ÖHÃ8õjÅrê#íÇ¦Ó¼¿z<¿z¡ò z
x@:Ğ M;2”.FèsÉ¤òıêR õl_Jµ"½˜À ğ@ãğª@¤)“œÖ‘Ôj#òıé¸o_Ò¦òıèòıÿ J¥u¹J$ MeœUƒšcÊ´Œ®_)Œgô¤	ÏZ ÏQåûÕ¦î6Â¸€›OZ(÷¥­S±6ddÔÒsØ~u#.îô AZ¦RˆÌmàŠBíR2î9Í'—ïZ/"”ü¿z`ç5'—ïJwª»+#ÀôÃÁ5!àš+H²¹Hè œœÒ…' ­“)DJB€œÓ¶7¥)Læ¯˜Õ@ŒÆ	ÎiJŒ`qN
M/—şÕ>do‘2 ?úÔ*çŠ—Ë÷¤eÛŞ«™›Äh@:óC.êpBzñKåûÑsh¢&P=iD|zT_½1úÖªF©HÆzÒAÆiÁ0sšB¬Iâõ:!æ4(ÎMAéÅ<'­^OZ¹´D•É¦lız±åÿ µúSYqÆ{SLè‚!+…?áHøÔ¾_½_½>c¢*Ä~_½?z˜EÇJ6gŒt¡HŞ#§ÇcOUÉÇJ_/Ş‹³¦(`@)***""\r" R"***(&ÁëR¬|~4_½%#x¤Gåç½=cÈ4â€®@üiËjÓĞÚ#`õı*@œuı)V<ŸZx¸¢èŞ$[=jE]ÔªƒÔ…03šfÉ˜Æ:Óvîş•&ÒGJB0W27Š"(	ëAŒgŠ—júRy|ä¥#¢Ë÷ &<Ô…éI±½*¯vo3ËäÓÙ ÷¥	´¥7£x¦5cR3ùQ·)***""\r" R"***(·úT‹¥Np(:"3Ë÷£Ë_J!îivŒæ­6tE‘ ôı)Á8ëNd$sNğ9­§DXŠ»»ÒcÖ«3Ö†Ò´LÚ,‰ø£Ë÷ı*U#šFŒgúS6‹lEŒ4¾_½9àzzÓ¼¿z5‹hòÇsNUÏíOUÇCš‹êmcb¨SR„év/LU¦l¤¬B«sO'm?fÖş”à™Í;³HHh!AœÔ›1NÓîoEÈÆqR OAJ#9§"Òô7ŒÆ6ji@OT¯=i¥jfÉÜb §„ÁÎia°iôÑ¬F2ãœÒQO`Hâ˜' UŒÿ U)Œÿ …*w¥#¯Òª-1#*ÆåM*T`=j_/ŞƒıjÓ7Œ¬DŸ§­!ùx5)R)¬20kXÕ3FAş‚”9"”&FsVâÇS$ëŒTŠ»»Ò²Ò©=NˆÊÄ˜9úP3˜Tô£`ÎJ¾cxJã0QH9©xù‡JZjGDZ°À¡)***""\r" R"***(8 yü)@'¥;Ë÷§{£X±
…8•%*®áœÑs¡KB"€ŒÖ…8)8¥	‘œÓÕÆD;O/Ş§xøëLØ1ZFFğv)B‚:Òìy~õªfêB'ŠNğ‹œbœb
)***""\r" R"***(Q¬fFª„ôæ•”špU÷ €x4FdxQÈşT*î5(ˆuœPbƒ¢#UÛŞ””ï/Ş•Woz¤tBCUAšäTŠ»†sC)ö«»4SÔŒ 8ù©Áp:f”&Nà¿.9Áâ‹³xÌA¥<”›3ŞœªLÕLr s‘N=)ORGZ¥cHÈ`Á<ÊœœÒñ´ dâ‹³HÉÚ;cò£h#œ~Tı˜ç­&2p?*¤Íã+Éæ— t{båûş•Wfñb•t¦°ÁÅHAE4¨4Ó¹¼d3¿Š23ƒÅ<¼šB›Iª»:#1¤Ú:

•ëN:š¤Ù²˜Úz'§4å\½)è„t¡£hLÔf$ñÏÖš[°4ŒÇ’qLgx¿Ïf…~ÀysëMŞ¸ÇZŒÉØ“MÜÇ©­1{gLñI½}iœôu«öcöœu9¤b¤p¿0:Pî@É«Œ¨ˆÍƒÒšÒ.y­Ã­FÜô?¥h¡rÕ!ûâô¤Ş¹àÓÖŒZÑS±¼Re=)***""\r" R"***(3põ¥ïO”=“Cƒ(<´„óM4Òã¦9¦{!ä İÀ¼šiv#RU¨–¨’&ºö¨ÎqÁ4³t&´QE*6&	çŠÜTä8Ï©EìÑ.àG'ğ¦¶3òÓ	'¾>´ß­ZJÅF˜ölwçÒšH=sùÒgŠ*Ôt+{
9ô5³ê:Ór=j¹©&J¤ •¢È=)***""\r" R"***(Qˆ{$‡³Œi…»“A94­j¢†©	¸€iWù¿1¶çŠnî~éü«EÄŸ÷t~î İşÉü©AïÒ«~É~îšåAàÓ2}¿*B}qMD=’\zf“+ıßÖ“#ÔSpIÙ²Q³?Î˜Ì M}èlzÖ‘E{	9â€	íù(­,‡ìÒ´uÛN=9Ô g&‘È'­4»ìÒS°£+ıßÖ’‘†F*”[(¬W1MfSï@@:Ó°=h£b•43+ıßÖœ„ƒŒ£¶7è*Ò¹\ˆ“Œ{Ò©¦ƒº)	'­j¢¬>KŠÄiUğ1ŠmJ!ìÅ#¿éIE¡|š
FiÇ89¦QEZHJ’½…!8äĞNi¬àŒV‰(!w¯­#2‘ŒÓi	ÀÍR‰\ˆZ)»Ç¡¡Ÿûµi+‹“QÔƒÀŒúô0QÁÍZH¥L=éÇŸÂ’ŠvÔ=BGJ(ÆZ¤ŠTÆ0ëŞŒ¯÷ZV
S@dÇOÒ¨µ
wò21MÜ½‡éHX“œĞRˆl>¢‡ÔRdúš2}h[‡"çš*Œâ‘Ü)äÔVƒä¿­/™íúÒ•›±½EZz•!X¡ç4ÒiH â“ğ«I)***""\r" R"***($5“šM‡ÔSèª/”iŒõ=é6QS(ùpE‚€äd^[Ty4ìĞQ‚z
wŒ‡˜ËELÀÒ£*qÈ?•Re(‘ÑO`1À¦…$ô­">Q¬	İ‡ÔT¡=M(Uª®ÊQˆyæ´(ç­; tÖRNE4İÊQÔm4®[5&ÃÜÒ0 àU£¨İ‹éMm£O¤(¤äÖ‘‘\—E;ËZP£*ÓL9İ¦šÊ¼*Fè~•àÖ‰Üj$L¤œŠM‡ÔSÂ·¡¥
IéV¤ÇÊ4 Ç"‹éNeÀÍ%j˜r(;Q°Ó©|°zb®2(UA9Å5¶÷ëŠq]¾”ÖRNkDîRˆI„`âƒ•=hqŠÑY£p¦”$çŠ“fG­&Ãê+E"¹l3aîiÆ9ş´»Úy«R‘Àh1©5&Îx<PSÒ¯˜ÚTc R*`äÓÊ3@R{SægDPÖŒ
nÃê*M‡ÔS‚M3E‹ Å;gy§QŒôJF±Z‘²ò)
p*FRÆ€xÇçV¤oD±úšV@zSöe¸éíJcÇ\Óæ6ŒHŠzS•qĞTàB®z`Sç7Š°úŠ
0âŸ‚z
#¨ªº: †$dQåŸZ/€¤”¯©Ñ¬7Ës@< )åNÜPªAÍUÑ¬D`äb” ïO ŸZ–éS}MãpòF1i¯-5”“š£x»‘”ã­9ıÚvÎ:óH£ƒVÍâYõ£Ë>´ú)§c¢(j ‘OU’zR`Ôà
©®èèŠB	ÂĞPš  ô?•9¹¦m† IÅ.ÃÆqJ¨AÍ8õú›­ÈÙ8æ…Œ‚ü)½R7ƒEŠqŒŒRÒ¿_Âšlè€Í‡4ygµ:Œ¸­§Dl3aõ¥8âF\U#Xî4'­9ëÅ:ÈªLÖ;†İÃ? g½9T€Aï@BjÓ¹Ñ ›¨£aõ&	¤¦m¡9ù¨(sÚœN)Ê›O Pj†,yàzTª”¢>21NU+ÖƒX´ Ò–°úŠ6QNìÙ‘‘JªAÎiT0iÀdâšlÑ)***""\r" R"***(dÏJP01NòÏ­=MQ¢º#)ãéV%Ç"HŠ4ŒˆÙqÁ¦”Éã§z”ã#4Ò3ÈıkDtÆC
ñJc‘KJ«M>¦Ñdevœ‘‘FÂy#Çšj©SÉ«7‹ ‹E+ Î)***""\r" R"***(çã¨è„˜Ãê)***""\r" R"***(Ò–šÙ)***""\r" R"***(‘T£!JqLeÏåÄĞS<Š¸³¢De8â„R£¤ÙÇ½&ÆìE_3:"Ø‘ŸJCÂª@ ÷¤AÍYÑÆã<Rùxà~¥IšÅö ´l_JZ)ìo1
Ô¥AëE'sxI84R…-Ò”!µZvGDd6œªsš
ƒÈ¥QŠ»5LFBNA¦”\óJr	"„óšÕhm43§İ¡XÖ–šfÉ±Œ6šBàÓÙI9yÅkvmX`Q» sN1œsÍ?Ò—iÆi¦i‘§_JU\œf'†Œ¸ü)ó#xÍ¡¡=i@ ¥¥*ERfğ¨Ä NzP¤ô£c{U_ChÉŠçš]«éJªNzz¨Ç"„m;ì_Jpˆ•ïJP“špàS4RaÇ~”2ãƒEH@=hO±¼ebœ‚)Ôã=)***""\r" R"***(<Õ&kˆãíHG?Ò¤ÆOJB ğF)§shÌe(\ô"PÎ(ÀRfñ¨íŠB<ŠqRJLÂ®æ±¨ ¥Ú¤ó@9¥ ‚©3xÌnÅRéûO§å@ˆ«V7@UÈâœŠE `cõŒÓv7Bs!<m¦“œÎ›¹zBÇZşPGø™ì“Ş:Ór}M#1Ç'õ«P°°âÊFi7/÷çMÜ§¸¤fZ(!ûûÓûÇó¤f_Z‹§ZRIêj•1ª Ä·QFG­ÿ 1ğ)***""\r" R"***(Rƒ)RCò;ccµ4°­(9ÍRƒ)QAFO­Säaì|ƒ'Ö‚ÀõÅŠŒòsMA‡±òXÔşdzµ7ç4c\ˆ~ÅŠ[ÓŸ­&O÷h ‚G©D¥D2})***""\r" R"***(.Twjc¿ÅI¸úÕ¨Øù± uÍ7#ÔSIZ¨«±cË)İùRe¾i´QÊ‡ì@õ¦œgœ¥:“jÕi)***""\r" R"***(Rå	¥zş4Ü.q»ô§šÒÅ*W8õ¤.1Ò†f)¸ÿ 9«I°w’sŠ(9ìi6ã«´ŠT¹ö£>ÔÂ}ŒŸSO”^Å¡¶ú~tÌŸS@Ër9«Š¤±?J\'©¤ØŞ”loJ´ı|ƒ¡4‡Ö€¬:
·CNÁìÄÀ	ühÉô¢Švdû& ôœQHÃ#ŠÑ"•!¥›¹ü>¦‚1Æ1H:õÅZV+Ø^i»
PNß”çëM$)***""\r" R"***(\v²bOSFAèh#4«·ø«DÕ;N>é4™>†œÍ“Á¤­V+LŸCKŸQŠ(y5Bä€ ÒRá½úQ…ş÷éV‡ìØ”R…oJ6dñZ$R‚Bc=ixà
Z*ÒEò*GQM##) ŒM‹éNÃP"Ø=M(@*M‹éMpAMOÂšÀu&HT¢´Š)BÃ)FŞù¡ÔÇó¤Æ9şuiX9®:…¦·#Ÿ¥ 9îqëšqÎi–©Œ%@Î3FäşïéC!ÎE&Æô ¥8¨=©6S@W=I§ìoJ´¬.Q›©¥§loJ67¥0äŠ]éHT¢¨… OJ]éFÃäÒŒJ]éFÆô«æ ÜAJséN^iv/¥1ò€UÇJ0=(àQ@ùP˜‚— t»Xö£czU¦‡Ê4Œ”ÒŒF1RloJ62*cQ"zPÑñÈÇÒ¤¤pHàU)2ìˆv7¥Ò¤O^)ÁzÑ6>R0 vÍƒ®?*“búR2óòŠ¤Æ–¤[Ò“Ë?İ©v7¥Ò­dEåŸîŠS &Æô¤¦UˆJc€)***""\r" R"***(&Öô©6Nx§P:V‰”ˆ'÷©>x©YÔy~õ¢cQd&?QL(sÀ«&<ŒfšbÇ%Z¤Êå+•=Å Óô©ÙxùE4ÅvşµjVR,AK€:
“Êÿ gõ¥ƒÚ©I\|¤myÍ0Å­X1•êi¦2z¯ë[)ÈƒË?İ GÏ#+GŒãò¤ÙÁ¢ÒS)67¥Jª=. «RˆŒ  ÊĞ@Çİ©|¼ÿ  ÅÁùZ¸È4 ÚGQIÔâ¦òıé|ƒœš¾diˆv1íJ#P1R˜ˆ¦„lò*¹¢0'<š8ùE?czPçšwfñ°Åˆ°æ¤ñÏåIµÁãŠ“kzQÌmÜˆ¨^¢€›¹ÛR˜É9ÅÒŸ35Qdb3Ÿ»Jc§„lò)1ƒŠjF±LiL–š## ©v·¥(Œš¾c¢(‰cõúPÑóÀÍOå³úĞb8ª”¢š!6àÒ„ Óü¿zPŠOO™åîÊ“ËÛÉ6Æô¤t8æš‘ÑèBàœbœ©ıÚzÅ“ëOTşğªL´¬1cë~´Ğ‡<ÔØ ëHÊsÀ«[Àˆ¡Ï©Ï"Q½?Zr¨ãšw±Ñ3Í(»O	ódóíKT›7ˆÃ#¥*ÆM?kÔ¨ÎE5s¦#<Ÿ¯çJcã‘RR0%N*®l·#ŒñKåŸîÓ•H9"Š´j·#hıF)‚>x+ôüi67¥ho=jB„õZ6?¥>…cxèGåŸîŠ0:b¤ö£Ë9İ·š»›DŒG‘¢—aÆ6Ô›Ò€‡<Õ&n®CåëJ#ãîÔßgÏ4Š‡¦j®b5#àçÿ ÕH#Ö¦	Æ £ÊÇğşµHèÏ,ã¤zT¡yı ñŠ±¢h„EÇNirEN"ÁÈZ_+'‘Utk1Wœ‘NEõ€qNX ÷¢èÕHjÆH¤hğjP…)***""\r" R"***(¹äS6‹#
:có§,|ômoJr‚)***""\r" R"***(©ˆS)67¥H‘({Õ§sNaœéÂ>>í(Œ‚šI£vJkGÎ@©
ÔljĞÙHŒG“ÊÒˆÔSÊ‘ILÚ2cqHÉÆH§°Ü1K³pÆ3Š­á+‘„ÏEà™ÎêxŒ‚•“ŠgL$@ÑûSv¼jfRy”ÜãZnt&F¨AäqN##ŠqF¨òÈiójoÈÂ’p(ØŞ•(M­Z•Î˜ËB?,zš})ûÒ”§<U§©¼YZr©Ï"œÉ};Ğ2N+Ecx´!U<bšQ³À§G$P<
wÓSXŒØŞ”ª¸ê)ûÒ•WE+¤mc#ñ¤©0=)
j“6ŒÆ§ëJ@§OQJ–šgDZc|tæ“â¥ÚŞ”y@EZfÉ¤Eè)BóRy+N0°«M¦G°Svyêb Òl úŠ»³XÉ
	À•SÖœgÍ8!Ï4ùc+ÁÎ()¾¥sƒùÒydUs¢#ÚŸ±iÛÒ”!=x§sx²3>í*®"ŸåûÒ9âŸ1ª„“À§ãiU@äiÁIä
¤ÍcRÃ6ù¥Xé“RäP«·¥4ŒÛ"r1FÃ• ôâ£
ÔéŒ˜À /—Ï+@V¥>´)I¡¦%ê*7 u¦'‘¢#“T™¬j(=Ç©Á3ÑE="üië¨Å>dn¦ˆ±ğ¤ò÷rLc´^ÑòÓLÖ3dK•â±ŒñùS¶ı})UH9"Ù´fÆí0?U‘NØ	éNØİ1O™›Ædf>zND<à~táEH±àô«LŞ5
¤Œ`úw¦‚£izŒÔfVêOé_ÂªÏñµQ'lã?:iî*9<`Ğ¾qT©²•L}¨çĞ~uá×y¤.BM_³+ØDš‘¶÷şUóïI½½j”`º"B¿í
k8)***""\r" R"***(M3cƒŠkH3š¥r}‰'$d?éMÜÃÔÏ3Ú˜ÏÏÿ ^´Pl~Å²míëFæõ¨€v£Íİ4ı™>È°O«ÓN3À¨„ÌiLøôªTÊöD”„6xoÒ£7ô_Ò›æ·©ü©¨ TÑ+nQß¥!bzšŒ»÷¿
BäŒJ|ˆ¯eäIED	ìÆ—§zjöL”Œ–‡¡ÏáLÜ@ê)¥Ô÷ı*¹T™.G¿åFG¿åQo_ZPAÔì‰)±øS2OZ*”lÅ!à»¿JP»0şğ§‚CV‘Jš M*Vı)ÌFÏjeRˆr…ş÷éFf¤£Õij?f˜ZM‹éKÏ üé'ªşµ|¤ûÒ”İª1“ÿ ë 1QÖ­AÙX—ıïÒŒ/÷¿J‹Íÿ kô¥Y2=j¹,?dÙ&ûß¥!#ßò¦™aAfê)***""\r" R"***(¶d.ĞÑµ})»ÛÖœc“V¢…ì€"“Ò‘ÕFyü)K¨ÍFHìãZ$ƒÙX6/¥ÒšÅlRsV¢™jšµ})
©é‘øSi2=E5tŸAáG|şT£ ı)€‘Ò—szÕ$O³TM5±(vR}x¦3ü?+XÇ@öc¨¦«‚9?¥( ô5¢Š%‡Üñ@Àèÿ ¥% g½RCäCğßŞı)ÁAèÔĞÊ3KZ$Í*¸àS
œr(2c‚i7/­/Ù†Åô£búRäzŠMëLj6/¥#€:
k;vÍÍ´Ò)SCé’)»ÛÖ•Xœ’kE¸rËƒÀ¤ö§ï_Zc0-ÅY\ˆ)Œ¸ù³JKçŸJiV'<Ò±\‚€	äâ—g½4+zxÈ b­4ƒÙŠ±©§ø©0¿Şı)Å8AÉq6ïQåûÒ`Gú	äC|¿zæEöhM‹éFÅô¥¢–· ›Ò‹éKERL|—búQåƒÑihÜÃ¿éU¨”•FqHÀ¥äóƒùR…'µ2ÔCĞÓŠ¯LP:b–Ã”o–GSúR4co&ŸÒšÌÀ5Z—Ê†l_JFN>QN¢šÜvDx>†ŒCRQZ!rŒOZPƒ½:Šµb”F” äµÄ)***""\r" R"***(4’y4Í¸_ï~”ß,uÆ}éiÊÀT˜ÜRåîš<±ıÓRõ¢­1r‘ˆ?v†Tâ¤¦?_Â­2¢®1”cM*O’Š¤Í9„‘Á¦ù~ÿ ¥Jà‘À¦`úÑXN#Bæ—búRá½(Áô4îƒ•‰´1Î3AŸJz3‘Hı
ÑI±¨¡_½!R1O¢­=GdG†şé£ËÎÚ’ŠÓ˜N)‘… c”&zÓé3éŸÊª2.£J3Iœô&3Å'—pjùÍC
ñ‚(Xƒv§· HªAÍZ•ÍTn7ÊÀZQ)***""\r" R"***(?8£©9EXAçm8ÆIàbŸzwzjW:`ˆLdwı(HäÓß¯áINçDP›W¦(ƒÑiié÷E;³U¾JÒ¬@p:œ«¢Ÿ34I‰ä¯­O§9çwfĞDqšA$dÔ­÷M2šlİ$„Ø3ŒR2¥8ÂŒCZ#x¡‹$Ò„­<)'ŠBê*®n’$c$RóÒà“À¥LÈ­)***""\r" R"***(b’"1àõı)V<rñ§º“È¥_»T·7ˆß,/ sH"äŠ’ŒJ£h±cû¦œíO<(^”\Ş,‰ çšaŒ‹V™•R)İ›&B"9çùPS·-#FZf±³"òÿ Ú¦í ã¥
IÅ!S•I›Áˆ#üiéºĞ€ŒäS»Õ£h±­'‘J#™4´U]Å°ò±ü4ß/'5*}ÑM`wp*®Í#& ¦:Qåó÷M=PpiÛN3T™Óq@ñ¶,v¤¢ªæÑØËÇğšQ~cÖŸE	»–·åûÒùxëNO¼)ÏÓñ«5NÃœp)È¾¢EñÜP»†søS|±ıÓO½:šv4NÄb Oİ¥ĞSéé÷EÌ´ÙŒtÅ*ÇÏLR°%ºR®ìàÕ^ÆÊB„”¢ †”èiõJE©"#?†€*R21Len€U&h˜Ï/ıª?zqò(«OC¢Œ0´yXä
} dã5\Ú›Äj®zŠRªGJZÕ&Í£-HÌ#Ò‘¢ ñü©ÌÛi*¨1|}ÒhÀÆı)èOJBOz)***""\r" R"***(òÁşK³<K—¿•<r)ŞÆ‘‹i¯ŞÕ*3‘JÊ­\[:#"·—ÏZR‹Š•¢ çÆ8­ã!9ëÇÒ” =)ip})***""\r" R"***(ZzÆLhŒ÷ş¢ zÓy©Ù¦m64B´†§¥Jß1È¤Áô4ÆVåÿ µúQåÿ µúSˆç¦(ÈÎ3ÍTM£44GïHTö¹`zfœ:V©)Ü`BzñR*îi0OAO
Jw4ŒÖ™£Ê)***""\r" R"***(ÉÔ»TŒ‚i0{Š»£h²%Œnû´ò€ôâUHÊÒ`÷â„îmìÇsùRˆÂã9ééN Š\Ó5Œš =ƒ¸§)=¿)X3sÒ­Æc6/¥!‹wNŸJw#ƒšrÓ4XÑHjÄ:~´»
ğ)àdâ”¡¹¬h¦4*‘È Eê)***""\r" R"***(< Ç9§ {dÑÌmØjÄàÓ¼¯öZ\Ô]€r3Tjª1¾_?v/ı“ORHæ—8«MšÆ£#ã®(*sÒŸ3Eh®Ñª’#XùÎ1OXóïNUÉæœ/J55S°ÓÑÇzO,tÔ¡r)***""\r" R"***(Nyîk„^_v”!éŒT¥éM«M›FbøéšQ'‘ŠU,;SÇJfªb,`c4á)***""\r" R"***(
XtñÏziØÖ5xŒæ™Î8¦3“É?­&şû«ø™@ÿ $=ˆşOÿ ®—Ö¢ó}Ío¹«ä)Qd‡â£#ûõ˜\ĞK‘‡²$Èşı5ù<5%5ÈI¡GPT®+6Ş1Mc“I’zšBH<øÖª(~Àvò  ’zÓr}V¹9\¡ì…ÀíúRãÜÓ<Àx'ò °ş&Ÿ)>ÉÚaA\õ4Ğøèh.ÔÔJTÇÏSA\õ4Ì·­.O©§ÊW±rFM5x"€XœúÒìoZ,
—Ú#¥;aõõ4Ò¸{1ØÖ ¡Ü(Áô¦3`à
µöw·ı¡Nµ>¤~»»T¢5H’ŠŒ±êMÿ Úıi¸ÙR«míLW'¡/½5TÇ1$ò1M'Ÿ¼)KpI50=ÿ :®PöcÁ$õµNhúÕ¨ÙR1ÇlÓ7ÿ µúĞŸâıiò‡²h)®2:S©
äõ=*ÖâöqJ††O•aìû\•æ–£ÉìiëÈÍ>Q{1h¢ŒQT¢ÎÁE!`sHd±«Qdû4+®3Iåæ“ÍúP\‘Ši©
Ê È¦ĞO©¤Èõ«å³°´RdzŠ\ƒĞÕ$/f§Zcg¹œW=Í&ÁêjĞ{46’zR°ÁÅ%hıœG© c4dzŠnHà¨úĞãÅRW³NÜÇ¾)ƒxâ”ô«KPP@ä
isŸJç ¤7;‡çZXµL7ŸANRÄg˜x8Í#¡§È‰
ÌsŒô¤çÖŠ $gÔRT sK±›œâ€ÅzS†îøªH\ºŒ*zu£i¿J~G¨£#ÔUØ¥†`ú0})***""\r" R"***(?#ÔR9éK”j)¥
[¥'ZUô4rD_/'
)***""\r" R"***(;¸¥POCO<ŒSbä#¢Ÿ°zš6SSvƒ(§lQÔÑ±OCEØr¥
[¥;`õ4Ò…¸rè4¡æ’W=Í©­cQE?`õ4 Ó»()FM.G¨¤*j6ST>Ah PlP
 ÀàŒTx#µJÀƒÉ¦°ÈÅh 'Ò•ÂsHF)Tá…pH0})***""\r" R"***(!u%5Ï¡I\mc½U­ŠQÔB œšMƒÔÓ¨¦_(İƒÔÑ°zšu*ÀÅQT˜ùP OAMu9Ï¥;$t4ŒAµkQE x§=ÍZ±\¬m>†ÔµCå#Áô4`ú’Š”ĞĞc$äƒRQZ"H¼±ïI°zš{ıãIM7r¹Fì¦ƒÔÓ¨­yƒ”nÁêi|¯cN
[¥>ª-ƒ‰@OÒ”ŒŒSÛ¡¦`ã5i(o—Ï^(1ñ‘OQ“N*1´Pİ˜¢!:š HSĞĞÖ©JæñˆÕ\t`úT€ÂŠ|Æ±M˜É9 ÓLx8©©6‚sŠwFÑÜŒF;f”)5'…)©jo‘àú‘A `v¥ “N
¥	ØÑ+Áî)\Øà	è)J‘Z§ch‘:bš±“É©ˆÈæU&ãfÆ,|äÎ‚íRPË‘ƒT¥sx¤3g4…u‘KV™¬v°úŠzÓÊ3HMj†±CXØJ"ïƒN(sÅ9F)©Å…
zRàúSÖ<“KŒqWÍ¡´PÀ¤Ôª™ëHŠZ}±²@İÒ¢o»RF)„pj–Æ«b0„ö§y|ã€u§¢Íb@UÆ)***""\r" R"***(>†¥dî)***""\r" R"***(4äU§sukàúRì8ÍJÔĞPcŠ´Ë‹!Ú})***""\r" R"***(9S#œÓºR¨ÉÅQºl@08Òí8Î)à 0(Ò’™¬wĞP½ÒŠJ´îtDP¤ÓŠKJF85JF±‘R(Ú})ã“ŠÁÅR‘ªw€ç8¥pHàR“ŠU\’	«R6Vr(Áì)û©¡T”ùTµR)Ø>†œ/JZ£T3ĞÓ—…éKNUg4›±k`UdŠ]‹éJ(ö¡;•¨m#±¥ÚŞ”õ(ªL¨²2ê(=?‘—k =ZgDH˜İ(Øqš}¢ÔŞ2±ı£9£`õ5jÈŞ-Á=r)áBô¥Ù¸fšv5‹"1À£`j@6Ò0ÎX®ftFBóó
Pƒ½*}ÑKM;˜›©¦”*1ÊŸEMc  ‚Š(§Äi,	¦˜şlõ©ƒM «ãµh™´d7fqFÒzfÿ v‘	Î3WwcXÈhFÏøÓ„dõı)á	R§zi³XÉ¡ª„tò¢¤¤*	É«[©;:ääÂ!<àTŒ€|Â…8ªNÅÆC<³ÜÒaÚ¦Ø¸Å&ÃØÖ‰³xÌÈ§…'¥.ÁïJ/Jq6ŒÄ+´‚¥nTâ”€x"?2şUFÑš îéN`Xpi@ÉÁ§ÇcTšfêW!*sÒŒ7¥IÄÑTm)***""\r" R"***(@Fr)ß…*¨n´à€U&#+•äÒ ©6/­Sûß­6Ñª˜‰œç RFsH ”zŒT)***""\r" R"***(M€ŒZ_#ŞÇzz‘´)±<£ƒ¸Rl#¸©”–4×R½R7ŒÙv£Ú¤ ƒHœÕ­ÍTÆìÈ½S”ÿ jQ•9Å]Ùª›CV6´õLõı)FHÉ¥§ÌÍ#6Åq)UAŠ\€zÒÕ­Ô†2c)<½İ@©2:fôîÍ#PŒ!^1KƒèjR„ô¤*AÆ*“Fª¢cT`gÖƒÔRwÍH•HÑT8òO©¤9ì)…˜÷¤¯ãü´ö=Çå¿»úĞ>”Ê?|ìPü¶~í
Xu¦QG {K“êi	$S¶ö¡œãMA±C²ş‚†<•Æç‘Iæ{Såaì‘&ÓıÑM#Ôb›æ{Qæ{QÊÁÒ=3ùÑå¿çI½}ij”	öB„aÔf§û´QúÒÔÔX{/ Ãzş”sê?*BÌ9ÛúÒäUr0ölr–ÏÓòş‚£È?¥/›ş×éO’à©1ùAF_ĞS„ôoÒ—szÑÈÉƒdòß¥1ş¦X‘÷©ÈÅZŠbGøS×¥'—ïJ9«²f(÷¢¸Éè¿­¡ìÇ… }ÑO¦lRùÔr•ì¬8ŒñM)œÒa“ši™ˆÅ>Pö@A#ı)
…3I½½hŞŞµj6dĞ”¡[¨¤ëE_+aì¢=C´´ÀÄt4ªY†7t¦¢/dÉÎ3Ú›Necß4›NqŠv³N8o¤åM‰êjÒ"—ôİ§û¢’ŠµäBí?İ «
@HéHÍƒÒ­!{+‹E7Ìö£Ìöªå³Hq Œo—ÏZPàñŞ–­DN|¿zP è)iÁ€è¿­;j.F Cßğ¥òıè.GUıiœñUËptÄo”ã¤$Ò—Á4Òã°ªå¦Ç…b9loJh”€)VV&šƒ²åûÒ†:Ñ½½hÜŞµª„…ìĞÓœŠfz’ŒŒVª!ÈÆR¨9—Ë÷¥§Ê.F-QJÌ9R:Á8¥¤,Z¤S»ÃiÆi)K“IL¿f.TëN^1íB}ÑR'İ‘¥ ‚ŸE-GÈƒÔï/Şš	)Şgµ)***""\r" R"***(\=˜y~ôy~ôyÔyÕh=˜“šhP@§ùÔŒÛ†1M+Ù†Ö=¨ØŞ””à„õâ¬~Í	±±FÆô§‘‘ŠaB)İÙ†Æô£czS“§ãKEÉqHaRM%IERH\ ½Ò”zRP	)!Ş_½5”ô4OZ*Ò%ÄiLæ›RPNVƒå#¢¤ö¢„Ğ’c“ĞR4dŒ‘Ú¤¢´L»2/Ş/Ş¦¦?Ş5IÜ\©ˆ)¥2sšpëŒ~¤•KB”Fy~ôy~ôê*®‡Ê4F:u£Ë÷ı)ë»ø}UìR‰—ïM ƒƒS±ÂšeTYi4GEIE_1ZÚÇµ”ú)¦™-!›Xv¤©	'­hTÙ+(XÉëÖ¦¢©h>TEäµœ‘VîŠZ®aYˆøëJ±çŞ¥¢¯™";ÒlcíS‘‘ŠhLæš‘¤b†ÁÎijJ)½¢’dL7fGÏ­ME
v6W#XÙiÂ3Œšw4ô$äš®k›ÅhEåûÒl9ã§­OßƒƒEÙ¬b@cù²ãKåç0œ
pCÜÑÌl’E/ŞœŒsRÎ)Á23š´Í'­<TÔ‡?…Rf©"¤‘LdÉÎjbëEZv5‘–ÊC” Ò¦Á( ¦ÕÆGDlÑ=©ÁsN§®ïâ­Q‹#¥Îje]İèa´ã5JnÆñHŒÅÏLÒ¬xşTìqÔAÈ§Ích¡¾_¿éG—ïNç½|Æ‹A¾_½Hcã­9z¥9:¥+›EGSJzTÄÖ‘#­;›-HBò)À`NQ†Á§?İ4Í„l	
gJ’œ#$g?¥Z‘´HÂzšV¹©pq´â„ûSLÖ6evŒÀÍ:TşÔ‡9ªæfÑĞ‹Ë÷§Šz‚)***""\r" R"***(-ÆÑØˆÂO õ§`1Šxô©©Iš&D±g¶iş_½:Š®fiF˜øàÒ;°iäfŠ¨ÈÕ]1Æ€	8ŸEZ‘¬d0.N)àĞQJ­·µZhÕ\ww¥òıé‚r)***""\r" R"***((sŞ®ìÙ7`òıéÊ§  zP3:Ò4LzŒZAœsR¯Aô¡=KNà½ÒŠ`$t4ú´Ñ¤U˜7Cô¨êFèi‹Ô}jã±²CJ‚riy9¥MEZv6‹Ô‰WiÎivîã©(§Ìj®ˆ•pxïNe+O£i ı)óA¸$ç© O½JPŠiMÀ°üê”âõJA$SÀÀÅ8Ïj¤õ7ƒ# “J«¸u§ĞA$U\éƒ úÓŠ0íO©¡úU#tÊädbšS)***""\r" R"***(JÀ‘MSÈªNÅÅ‘„lóJc=›pÆ(S´çiš¦Æªí9Í;czS'µ-h™q–£|¿Ò/ŞœI'$Ò«mÅh”´#(Aâ”!Ç&¤ÆşsHr§ƒM2Ô†ìÇëI³œsÇ½ ‘Ò¬Õ67`Å	ëÅ:àF*Ò±¼&Eåûş” mÎiá0sšq¦l¤GK³ N	ƒœÒĞm2=»¸Å&5*Ç¥(GNj¹™¬jXŒ!=x¥ò¶õæ¤BNsKBw6B"ƒµ'—ïR³m8Å
wâ¨ÓÚ25‰²5"go4´àøÅ‘˜ÚpLŒæœFiÁ;æ‹Øµ @QJÈ­)éAu Ú5„çG•şÏëRR“Š«šªšˆ9J÷©vôñJ9ªLµRäb0x”DËïR¨Üqšr®Şõ¢ÔÑNÄb"FGZQ:Š•Wwz_/Şªö5U,D°Œç¥À5*£¥ªÜÑT!òğ0x4÷©àãàr3A¢™ˆ÷§¬?İ§SÃn¢ØÒ5<ğ“IÏ üé{Ro>‚¿9Oó[ØçĞ~t¼Ó7ŸAK¿zj£qÔTy>¦ŒŸSG ı‘%.â8˜¬{äÒ±ÀäjjºB’Ç¨'>ƒó¦ùŸJ<ßqO^ÅçĞ~tsè?:o˜}¨Ş}ìXî}çN¹LIê)Û›×õ£•¡:#Á'ªâ†=¶š7ZiN1G ½“€>á™=…^:ŠföªPaì‡ÑH­‘É¥ªädäàMÁ=*†?ZN"öVMbAá‡ÒíšiV=qT ÈMÍÚ”Ï?ÊšF)***""\r" R"***(.O©ªQ²¦z6QI¼ûR‡'Ò«‘ì˜›¨§äP(æK€ŒHtô¨ËÑiî	änZ¤¬?f7qşá§ÔQUËpöby~ªiDd€ir}M>¦Ÿ+²aƒİMŠôZLŸSùÓ›8çÒ%Òf ãm4É“œR°ÈÅ0ŒU(‡³“ŒS‡NµëN.q…ÎjÔIt“E4'‘NªQdû0£ õQT“fÄÀô`z
Rxÿ ir8§f/fÇ`zQLŞŞ‚çĞU$Åì›E"’z‘KT¢/fĞ»Xõıh ƒƒFæõ¤É=Mh¢ì>@Àô¤ÀôÆßìŸÊ©BáÈÆ° ô¤§ätşTÜıÓV¢Å±2}MILØÔúÑ‘…í‡ÔRlj­‘‰E.¡¤ÁE;ˆQEX|AAäÒŠ]Üc‹)***""\r" R"***(A)***""\r" R"***(Àô`z
Zr G"§Qò!8ÅH±£šJr¸ì/fƒaõl>¢—xô4 äf•ƒÙ¡¥ É¦Ô”`zU&ÑJt«÷©ø‚ŒJ,ØœX`z
F`
PqÚŠMXÍéJŞ4ê(+qÒŠ?J)ØN"ªdqŠ]‡ÔR§OÆ–Ÿ)Ÿ(Ï,ûRì>¢E-•)***""\r" R"***(ŸZ
ÔêvÃê)ó•ùOéFÃê*j0=_3*!Ø}E¨©°=5ÀM1ò¢"¤rhÁô4ú*…Ê†l'¨üévZ‘ 9È¡“'ŠiØ9H¼¯aG•ì*]‡ÔSHÁÁ§Ì+22¡OAF¥IéM(sÆ+H»–ÜAF §ØÒ˜Àëš¡ÙŒĞS¶QNÀwAf3Ë>Ôy^ÂŸE1†<v_û5(R{Rì>¢©6†¢EåŸîŠ<³ıÑRì>¢‡ÔSRÔ9Q	L)***""\r" R"***(?Ùı*u\uÅ. «RĞ|¤<öy^Â¦Àôı)vËMI‡-È<³íK°úŠ˜¯¨ı)0=*Ôƒ–ÄE=)***""\r" R"***(&î?*œG‘œ
]‡ÔU&„â@#ÇcC/ÛÏÒ¦Øi
â©H¨¢(‘œsJ±6y- ãš®m)***""\r" R"***(ã2¼r(ÛşÏéRí-Ú†P¸Å6Š *ŒSü²=*A=?
 xÓ±ÑªàsK€zŠP¤ô§*€9¡A<
R§à‚ŒÛôªLÕ"0£²ş”ğ9áì)vQZ&ZCBƒÑJr0EI€:
j£U±Œ“É£Êö6Õô¸‚ƒTˆÒ†â§Àô×^8JF‹B#Å* sÅ<N(‘Ó¤YºÕ	A õæğ)“È«LÚ:	Óİ£~x§‡Á§m‚©3x1›G]¿¥‚¤À=EAè¿¥RfÖº«»½? t#¢ş•& «OQÇB24İ‡¹©¶ƒÑJ_+ØUs§b¹ Q°‘ş5>ÑıßÒ•SÛƒU{Å•ü¯aN ŒT­ì?*@„ERfÉÙ‘á}8) äSÄyşùS•1j”•Íb@ ô¡—#üêVŒç"/¯5\ÆÑ"òøã­[TØ”¡7ñM;š¦D jB `QéTS#£âŸ€)***""\r" R"***()¢©3x¡ƒîJ“¦(ÀôIØÑ;
Oj
OéĞQT®ËL`œPÊW­; ) õ¢ØÖ.ãK°úŠ~¡¤«æ4MØE‘ À8¤QÇ"£,(æ..â{â½Ò— õ$õ6ˆÅ]İéàĞR¬dŒt§à‚¬İ4G‚:Š6JQF¥Z¹JC $â‚„tæŸœâjf±dtSÙ3ÛšELjî“ ç"€:
0AA)­M"ìÆ8 ğ;R`c¥8¡n§š6{S±¼Z·æÏ¥Ç8§€;K·œU­)***""\r" R"***(ã""÷E8!=GçOÀô§*ñ“M6m‘ËN*Gj‘G‚;U¦Î˜Ìˆ¨=©­p*b ÓJÕ¢lµ$D?ÃúRù^Â¤ Ÿ”zÒ„ óƒV¶4Œ®DPŠ“S„àKå{
«ØÒ2±M¼0¥Àô0Œ½Mh½¿*¤îj¥r§9¥ÖœTÔ˜8Î*Ó./PÀéŠiCÕ*€W‘K´‹úVœÆÜäHŒqÖœƒÆ*M†œTc¦¤R›!ÚÙÆ((EHr§sIŒu­¹¼f0N)vQNÀÎq@8§toÜEVœRÓ¶QB¦4))***""\r" R"***( Ôï,ö4ìAJ †š4ŒÙ—¸ Dİª`=@¥ ”]šÆdA¯éNòı…HªzñøÓ± U&hª¬Ly"œ#8ëOéĞS×kŸ¥'sXÎãL\v Æ{àÔ¡1É4â¾«úR»5S+ìÿ gô¥ò`*lOÒ—ÒÙjd"&Ï"”FTå‡çRh «LÖ3dj¹<OUÇ\Rà‚•HE]ìk ì(©  ¤()***""\r" R"***(ZhÖ2Ğeï,õ^iÁê¿«RFŠh`<ŸåKå±8*E8Fq‘Šw-L‹gû?¥(„õ TÁF:Rè)ŞÆŠg–’ßäÓCç4ã =©7î
şKöv?Ïob˜¾aî(ÇÒ“pşà£pì1UÊ…ì.Ã¨ »¢ÈGS@v<ƒUìÃÙ$=Kwãñ¥ËíLGZr9#Š—NÄû!wf“Ë÷§9Á?¥&õõı)rè‰°ÿ zŒ8>´»×ÖëëG+²bşõè>•ÿ jxvÇZN²hµv4İşÔ¾sgÕ6/dØl_J6/¥sQç5>IØ°
àRçÚ“ÍİÃQ½}iòR1!iÁ˜ô™½}iÈàgÑÊÊÃ†ïâsÔg(ó=ª¹Eì®!FÏ­Ò—Ìö£Ìö£•‡²°¡9Ñ±}(Z7¯­¬^È^”¸ã?•7zúş”ï9Oj9CÙÊÀt¦á‡LSÙÏ^‚›½}jÔDéØo–}¨*GZvõõ¤f\c­U…ÈÆÑHYsÖ€Àœ
¥û1iK0@¤¥Êÿ wõªP¤5‹‚šrÇ8ü©Ä·aBîÇÍV¢O²C@¿éJ¸juùP{4Ö€ÚŠp|b©!:H
Œ”ÓyèEH¬¤t ô8ªQ#Ù¢&Å7czT›ÒéUÊ‘<„ayS¶/¥8©‘IO”N›*@ c±ıih¦•…ì˜QK½¨ŞŞµBöBQK½½hŞŞµk`öbÁ£üšr¨#&œZCöh‹ç4ñõ§R‚Qš«\^Ìi óùÒR1Í8ã°¢Ÿ+f0rq¸Ó¶íšZ)¤Í	±}(Ø¾”´UìØ›Ò‹éKN\7i=ìô±})@¥?búQ±})] Êr¨Ç"EQû16/¥×ó¥¥£44Ì_,ôï+ıŸÖ”;f½}j\Xr4Fbã¥'—ïR–SÁ4Ÿ»¡+ŒÆ{MéR6âöcV0:Òì_JZ(°ùÓÎE_½J2zÖ‹éEÒ(ÄC)v7¥< :QEØ½š
Òàrœ€iÁÆ94…Éa¢(ñ“üéB)èiÀŒtÍ<ÁÛA<ˆŒ Ç›±½*Flœâ’­4G+±½)N9%¹éNé)ÑıÓFÑıÓS€„àPê ÈªR¸ùQ
¯ ÇãFÖ=IK» UcûRÉ9+ROZ("#òÿ Ù£Êÿ gõ©(§v>R=˜<có  =qùÔáT”l_J´Ã”ƒËŸ­Wû?­Oµzâ‚ õW‰•şÏëG•şÏëSí_J6/¥>d¨ƒiQÒŠŸbúQ±}*”®5ÈTy§l_J“búQ±})¦>A‚0z-!Œ¢¥¤*	ÉWcQ#Ø¾”¢>áiûÒ” 8]…†ò9…'•şÏëRQMI ä#òÏ§ëNOQR¨ qNÕJLN,€v¦4}È«ÔRàVŠCQE}€ğ/—´r*aÎM.Åôªæ7„H:Q³qéS2tR#¨ªLÙ+”4†2z¯ëS 9»W¦*®ÍÄ"28ñÇ"¤ E;èiÜÊÿ fc‘OUdŠF?ÃŠiÜÚ(hP:

©9"¤P Î;QµsœU'cDˆ„dõ À@ëVv¨ç‡aÍZ‘¤JÛ=?ZvÅô©hE]İ)s&DPÅ&ÏöªÃ¨LÚ½ÅR‘¢W!àúRªuÜ*]‹œâ–®27…ÈZ<ŒŠh‡AVœ 04ŒŒÑIØÚ*år0zsŞ•W'$qSl_JĞUsÅØ`ˆ78¥X°sŒSéÈI8Ïjµ#tÈü¿zw•şÍIOÀQÀªL´®B±‘ÚœTc S	éŠQåôjZš+˜²rVœ#ÀëŠ—búR€®ìÑn@T´›wqŠ™À4ˆ84ÓĞÚ${Ò”§j]‹éKÖŸ25¤Y#ši@;TÎ <RÙ´^¤[Ò” 8)H`Õ©§q‚<óLhÈéSO
¤t«R-¿Ù ¨'‘Sí^Â†EÁãµRlŞ2er‹Ú&¥L !PNH«Næ‰êG±})6=*` àRmRsŠ¸š&C±³À§,y÷©qÔí‹éOšÆ©ØˆÇÇZh‹Ÿ»V:ÒQÈJLÒ-2=€@U T¤gƒHgÍZhÕ4"ª•»Ò°ã4*¬h˜ª„x§l\à-*ôJ~Ğ àU¡†2y"›°ƒëSRäŠ)***""\r" R"***(“Da<
_/o8© GéEÙh‹jqFÅô©6©íN@	Æ;Us3TÈV0z/ëJ##€µ>Åô¥ ¢­JÆ©Ü¯å³úÒŒTÎ <RÁ­F‘lŒD!ZM£HéR€œHÎ*®kˆ¸éOHøéš(R\gù¬mù`p¢‘¢9åjÅ)***""\r" R"***(Ğı*“ÔİM•Š˜Å7Ë;¿­OMe dU+š)êDcç ~4*`òçRxšP¾«úÖ‰›FW«ÏK±½)Á@9–©lh¥a…èi:Ô„‚p5“¸?…Z±´etDàg¤	‘€8©#¨ }*Ñª’À§(µH¸Çœ ÍZw)LhU#¥X#Ò¤Ø£µ@íLÑ2'Lò4®N1ÍNUOQFÅô«M´mAäß4¢.øæ§ c¥;šÆmªüÂœ´
€zÒ §vn¦†ù#Ú^‚ŸOØ1‚3Nå)¢éJ«Ç T˜\à®?p p(æ5SD` 0(BFAü)ãéN]§ ÁªORÔˆÕ~aOHøô©piáè)¶Ù¬ga¡	ëOò³ÔSÔS¶°íHÕL‰¡À¦!ºqS6v½i1İÇãšhµ1› ÃC(=H¸ÇµJæÊ¢±
ÇÏ#ó§”óéR‚½Å8(*“eÆ£#;óFÅô©zQM3eWA22;Q±½*E ò?8(#îÕ^Å*¨Œ ‘JèIÀ¥Q“Ó5JE*¨b«g OH½©À :cñ©9§^*“4U '&“zúÓ|ÃŒJnáşE,rŸÂŞÍö$Ş¾´›ô¨Ã)àpb£‘‡²ò±ìÿ ¥ sŞòsE>V/b;Ìö îÇÚñÍ¬—CÈ]íëJ÷ÍÃÖŒQOÙ™º7$¥'5sŒOäÔrØÛ ´RdzŠ]ÃÔSQbƒ§4du¥ÜÇ½5ˆÁöªQ²A½}JUnâ¢,æ•XpÃš|‚t´Øœ6FqÅ×Ö£S‘œPÍ´grìI7¯­*¿÷MCæ{S£“”ùØ“+õÜ~”»×Ö£;Ñ‘ê(å%Ó$Ş¾´o_Z` ŒŠ(å²o ıëëFõõ¦†aÅÛÖ—({+ŒÒá½úSCƒ×ŠPËœdQÊ/f8‡ìi
¹ê)ÅÀ<sIæ{Sådû167¥É¥ó=©Æ9J.âöCQÖ+‚œ\v zŠÓ”^É‚îş*Z)Á¢İ„é;E&G¨£#Ö¤{6-&õÎ3A~pi­“Ñ)¤G³`\çƒ@r:óIœuw«H9 ÇqJXöoÒ’;U¤K€»ÛÖíëIEBäBä±Á4¥cH¥GQøÓ·ï`à7czQ±½)Û‡÷‡÷“ìØÆV®)¿¼§±úÒVŠ"pbOQŠZ(üj¬ˆäwcåéKûÊà2åF_ßòª@ıå*îş*QÓšLÿ œU$ÃÙ‹Eÿ •ÿ •Pı›
(È÷ü¨çÒªl(¢ŠW³
t}éCu§‚“»³Š2=ÿ *3íG+FQŸAIƒëM+)***""\r" R"***(S¸´QƒêhÁõ4ì‡ìÇ‚ã¨¥¦	ê3OÏ¨£r]0¢ŒÊŒÊ‹‘…ªøÅ!9=(°ùœ€äSiT°è(%ÇAàĞQJ‘‘F¡¤ÒfN"QKƒèhPC(I!XUPW$Rì_JZ8ïIÄV`)v7¥(T#¯ëN©„*QFÅô¥¢§™Ê„Ø¾”7Ê¼Rı#¨ªZ‡*¸Á»9iHsÖ”¼œÒeıåZ+¡¨&&Æô¤ ƒÍ=K´§‘Š®`å³#¢•ƒÆi6·¿åUr¹B”+œRcÇ4õWBqt¢Œò(È÷üªÔ…Ê»Xv§Ò”ò1G0ZÄtS™ yÓ¸íq ÉÀ¥*GQO„Ö©4‚Ìeı‹FÁêj¹ÒEHª riØOSUÌ>TCJš”*„Ò„ æ‹Üj$kFqŸz_+ıŸÖ¦É¥Ø=Mc!ØÃµ(BzÔ»©¥XÈéúÑÌ+m_J6/¥NPšc®y«R)DŒ Ç!Ï"“‚)Á@éUÌbG±})?º*R€œÑå×4ùDA ëÍœğ*]€ŠZµ;šÆ$%x£czTÛ©¤òÖ©HÕ"5µ)PNH©6SFÁêj”‹I!€``RíoJpPE9W=sT¤‹ˆ„db˜PŠ—`íA@jÓLÒ7!ö§*‘É§sšP„õ¦h„Ö“hÆ1Rl¦‘“ŒĞ¦ÑC@ ¤Ø¾”ìCJ«¹«LÙ*QFÕª@ Q°zšÓ˜Õl0€x4ä/ëJTîÀ§(ÀÅ_6†‰²2£îã¥vœæ¥SRÔÒ:ÔĞı()œq@kh»›Ä†•z­<¦y Ò æ´H´˜´QEYkp ´€ x¸'¥ÇZ.QJª­<ò1Ik©¤HÈÈÁ¤ `ŒqR bšTƒÀ5q6LaC&Æô©B2sFÁïT¤®jµc‘J8íƒÔÒì¦õ4NÃv7¥‡…<g8¢´LÕ2„t£kzTÌ óFÁêkDìmE³ŠM•0P¤eî3V¤h™©‘N¥Áô4ª¹ÎEU×SMÑR…Ü)***""\r" R"***('’}èMš°ÔPG"”( R…ÛÅ9}ê¤Zb$dR¤£anÕ¢lÕ6F8'^(XÈè)àéT™ª›PŠCRRi¦™ªw'œªsÈâ©ü$R†„Ó6‹±})@  ‚:Š0OAWÓw
)Ê¹ÎE8ò1T·6ŒˆŠ‚rEF1*MƒÔÑ´cv±i¶ÈŠw•*‚š”R`g5IØÚ2R/Aô¤(	Í(S§k›&¬.Ö©ÈÅ83¢•”j“4R!*E&7qŠ”)Ï Ó¶ST™¢‘ ˆƒ¿­.Æô©‚FÅ«LÒ5v7¥8(=WI°Q±}*ÍTÈÊãîÓ#­L~SĞŠiç¥RfŠW#£ËİÎ*L`óšríÏš¥+ÆV"ÀcåPqÎ*Z*¹ìj¦3kÔªŸŞ @FiÔ)³HÌ‰”¢šPƒíR¾sÒ)&µR7ŒÈÊñFÆô©¶SI°zÕó)ªüÂ—júTŠ˜<fƒèhæ-MˆÁè´ÿ /Ş†ô§ì_z9ŠS¹zÒ…' ©L`÷¦ùeG5F±„1È¥Xÿ ‰E9c)***""\r" R"***(ŒÓÊ?Âšm)ŒPAäTªAPc‘NH±Îh»4Sî&	§ı3šxFôüèeÁàSR4UÊ2E!àŠ’Š´ÑJ¡AœK±½*EÆq·­8¢Óæ-TdAGuıiBĞT@9àğMRw4V"!)v7¥8.:Kƒêh4öƒ67¥ySÇzr¨ÆìĞ567Å&Åô©i@NäÕ'ĞÑNÄa8ğ è)Û÷4ê¥¡¤j'E)***""\r" R"***(*ôÙùRâ¿™9ã¯`ÅÀ¥Lg¡ 2ã 4¡ÇLb©D‡E£óH\
Mÿ çù	ö6ç¶(ùı©g¸ü©wQG!.|şÔ|şÔdzŠ2=E.FÉ€İqJ)2=E.Aä
9.'I…QG³'Ø±à“×…5úç¡—Ó¸”r;’èsĞ~4 GaøT„ 2 ¤Ü?¸)òéXm»‡÷‡÷¡ì®%' ¥Ü?¸)Cü4r‹Ø´({ÒĞÅ!`)***""\r" R"***(·±¬ Á£Ì†£Ş=)***""\r" R"***(8Fhäb?,yühùı©7Š7ÿ œQÈ/bÇ
]Ç°•4Œæ§98zSä'ÙXF9=¿
LŸZVaŸ»IG).QŒÑFqÏR‰>É€”ªHè(Ş@)CÛòª³3tØnîş”ªI<ŠO]˜ÿ \¤û66 >ßJs`1IMD‡&ÁêhÃ)h8ìiò‰ÂãNGğÊ)=±O¢šV'Ù‹ƒèi)ÁÇåH[ÕERD:VŠ('ªIÈ*ŒœS¶S@@)h°¹›©£`õ4´P{6 P;PPvr>è¤¦›`õ4l¦”qJg••4/f S¥Áô4àF8 QŸö…R!ÓÔfÌŸ»úSÂFÚ£oSV›aÈÄ(¦ƒÔÓ˜‚x€dâ›ZMƒÔÒykRy~ôy~ô¬„{Ö”(©ş_¿éJªQE† 0AKµ±œSğAEPùm>”"ŸEäƒèh*Ãµ>ŠÉa˜>†” <äÓ¨ N"ƒèhRQJ_ĞP“T&¡£ĞÑæJ]çĞSåaÊ„PsÈ¥)”¡ÁëKzV±${HíN@Fr)Ôñµº/éA.ªã¦hÁE(m½(ŞOP)Ù³LJ)w²?*p*G8¤/ga”`úSÊƒÓô¥	ÄĞşU%(Çzzìÿ õT2Hö‘ÚŠ‘±øSÊ?*› ä¸€àæ”±#¥'GåJTÓò«ZSE?`õ4l¦¨|£ '¥8'©¥
¥-q`õ4l¦–ŠÊ&ÁêhØ1ŠZ]§¨.ƒvSG•ìiê£©§SM¡rŒç·çKå'¥H¨äƒHÜô¢ìFyj:PP‘OÁô4„ÔQv>Q˜>†ŒCR(ÉÅ;`õ5WÈUrpA§l¦¤Ø=M^zSL9Hü°zf+ØÔ»Hè¿¥.Óè*¥$.QŠƒŒRì¦œJxUôªR°ÈÂœp(ÃzTÛò¦/Ş›w%¢0€ŒóOÇ¥9P
 yü)^ÄØ£$tı)=?*²Uq÷…1Ôc4ù•ìhò½J “‚iŞXõªR4HƒÊç¡§˜J¨^iH¨§Îi©[ÊúÓŒ\t0E¥1Šqw6I²¿•ìhò½OåûÑåûÖ‰š$È<¯cG—Æ0j/Ş,w5¢‘IÄ|óNÚGcR<S‚uªº4„[O¥L~U(Œw42¢­HÚ*ä+qùÒàúxàŸÒåûÓæ5HŒ!=ivSR cÖ\sš¥#D†ì¦ƒÔÒãœÓ‚Ö©3D´#)èi6ŸhWô¤*1Ò­;š%b§Å!RzŠ”€¥(@y´LÚ,ŒF1Í¥(À &_Ò­¤3i*¦zæ1Şœ#äÖ‰ØÒ$,„õ©¾Xõ5ai…ïŠµ;3TGåz<°:æ¤
.ê*Ô®R¹PE.3Û4íÿ ¥*®ÓœÓ)IW 4¡I"®îô2ã½4Í#-Hğ})***""\r" R"***(N3O¢ªèÙHÒ—iÆjP™Í7ãŞšzšÅÜiô4`‚¤£ t«RÔ´ÆmoJ6pjEPO=©YG_jµ$o”ëM©(USõúU'sdÑSÇ—ĞÔÛ1ŠO/ŞµRĞÑ5bJr®zæ¤òıèæ‹²“!Æ@ÅO¥LŠO/Şšf„-l~"•S¶)***""\r" R"***(Jc0sš´ì\ZåıiB1ƒRŠ*ÓfŠCB)|¯cO	‘œÓÕAëVÊR"ÙşÏéN1®8©<¿z] F
f©²§84» "¤)“ŸéJĞ~TÓ6‹d~XcÒÅ@ÅL¨	À¥d fªèÙ=H6QI°Õ…@İ‡åKåò+X³X»Õ29Í.ÁêjV‹°¦2‘ÍUîk7`õ4Òx LŒæ—ËéB¹¬YAsNï/Ş” yª½‹LCÁæ“i¦
^i8È?¥4ÍS±@¦í>†¤ç×ô¥ 3V“-HŒ)'£iô©JÆ‘Wø}*Ö…¦FÔm>•/—ïNÀôJZFD",õ¥òG÷OåSª©©
p9¦¤Z‘]£Ç8¤òÿ ˆÂ§*)***""\r" R"***(3×¯áT™¬dDÎiBRàz~”¢ Fxü©¦h¦GƒèiL`ŒdÔ_¿éK´z
²ÔÈJqFÂ8ò©ŠƒÔRÁÎj®o‘*qŠp‹·?Jª	éOƒÀü)6j¦@#*x—ĞÔ¦&hòÛ¸ÅR“+™25\õÍ(P)şXîiBqÀÍR‘jVè(ĞSü­Ãå )^)***""\r" R"***(ZfŠCUyéÂåäcëN	¸g5"Æ6äwfÊV!ò½8FqÖ¥òıé@U)"ÔØĞ„Ó™§¦;â†
yP‹ŒÈZ<JMƒÔÔ´`z
´Ñª‘@¥Áô?•H~”í£ûâ©2ÔÑ®N4ï,™© ry¥ÀW1Jc6·\QƒèjTÚF1NÀôsª„SÏ4õCÖŸè(P3”sªòØ úÒˆ¸èjeUÇ&—`=f_µ!
@Æ)***""\r" R"***(=Pqš( ü©Ê ÷ªR4U.x5($µcÏ<Sw¯­9{;ŸËÄŸxô 8î*e'“OzG³±‰&õõ 05åèÜ¾´rº(“zúÒ‚CQ©SÛ4ğàûSä3t,-›—ÖëëG(•hÉõ¤Ü)***""\r" R"***(<lÇ4(•ì…=ii¿»¥J\„ûÈÀg4óÀàSã­gj|†r¤)nÅZiÆxséúÒsè?:|†~É‹EúRmİ.AªL	# Í-7hşèüéÔrØ+‹ŸöÍ&Iêiw‡š2¿İıhµˆtš ™Í.Ãıê¨
\Ê‚]6(M Òœ Æ:]ëëR×¹£J?ŞÅ7zúÒ‚AâŸ(0n¹4…˜ëA`)***""\r" R"***(×Ö„Œİ1<Ïj78"—pÎ2)zöüªír9@ä
Z(£”QëşöiA”ÔïƒOÁã4¹IpB`´¡‚ğ9¤¢Ÿ)›Šæ{RøqÍ%r’é¦‚Š(§ÈÉöaE:ĞqØQk	ÂÀiÁÉè´ÚU šd{1ã$r1E
Açµ;åôì˜Ú)À¨¥Ş¾´Ù±„ÖŠW )***""\r" R"***(4±j8‘ŒbŠ@IŒRõïNÈ‡ ¢œ¨¸â—búS'eII±})èê*Ğ8—ï@LæE2=›
(9íJ„qÇ4¼ŠTÄ¢¤¢ŠölŠ’€G"€öle§oaI@¹BŸtSUsÉéO ¸)“œÑåûÓ¨ÃvZ	ååûÑåûÓ€nëNØ}E=Pr
-;aõl>¢‘J#HƒH9§"„Îy§Ğ—@	æœ«·½-9;óHÍÁ¶"’¼â—Ìö§uéE=pX«J0Èâ@Æy4„à Í-/ r¿8*‘œTóà2«·½Òç“I»‰Ài¦ù~õ!Œö4l>¢Ÿ(œl0&sKŸJvÃê)6QM+”JU3K°úŠURM4_½_½: *[v™—ïJGj–ŠAb-«éJ01Š’”!#4Öƒ±8&FsRl>¢…Lu§Ì.[ŒTÇ½;czT‹·ø©ôœƒ”ƒczQ±½*z)s+ sÍ»GZœ€F)***""\r" R"***(4¡Ïj¥ Q±)***""\r" R"***(:>õ OZ]‹éUÌ¬W*E8 íFÃíBbå@8*§R„9æŸ:&ÚŒP@Á§„ÈÎiÁN8»)***""\r" R"***(×® §„¯4¯5"Ç¢›‘6dEcG—ïS´|u¦2ã‘M2’±Læ›Rbx)Œ)***""\r" R"***(it\QçL}ÑMç¸¦·6ŒBŠP¤Ò„ãš»£h¡´RAÁ¤ú
i—f p(ö§"÷4»Tö«R.1! –8§?búRôªS-$GCĞÔÛ¨¤(psŠ¥#U¡ LæN)JzRªõ«LĞ@ƒ<š<¿zxBFi|¿z¥%cD›D~_½=ãŠSìiUv÷ªL´1ãß/Ş¦e›°úŠ´ÍbÈü¿zB¤T»=èsÍicDÈ‚’2%O°f‹éZó#e"	è)ôğƒ<ÓŠj¯sH·CŠeLPö¦:kDk”S¶QJ‰ÓÖ®è´î2•FãŒÔ»¨£aõs"†*íïA õ©Jõ ¨5qc[°ÚqšLqÕ.Æõ»­Q¤wŸtRÉëR¬y84ï$z
iØè‰
Ç“ëKŒqSğ1šmZhÑ+‘ªœQSl>´ÜÔU§sX‘‘‘ƒH‘RĞN*“±¢d`dàQĞâ¦Ø}i>=j“¹¢¹Ç¥òıéB9"œ«šÑ2Ó]İé|¿zvÍ½Ö†©¡„`â”&FsN¥HÍZw)1_½sSªpi|³ÜÕ&RÄ\
xLæ‡ÔSÂ–éV™¤X„db›³ç½I°úŠFBj¹„dbši4ìö£à÷¢íš)ÔQìE9S¹«Z3x´†*íïKR,jÔ4j¼b­I\ÕI\¨=©å=)T0jÓLµ$EåûÑ°b¦§ÈÎj®h¤WòıéÀ`b¥òWÖ“â«FZ¨0.ài#‚*]††ão^ÕJæŠz(LæÑœñÅ*¨µ¢vFŠC±ÁÎ•FN*U
FZ
ö¤ZÀ RÓ‚zÑ°ĞjÆÒªîÍ=SÒ°úŠ¤ìh™Æ:ş´(şSù©B)8ÅRfŠI‰íJ#=)***""\r" R"***(X‘ÀÅ(OZµ$h¥b%z<–«Òœa«šåó¢¨EÏJ—ïR”1ŠO-Î(»5R#	ƒÉ§*Ü
“=©UAäĞ›-Lg—ïHè æ¤*qš $â«SE2%Zœ"¡©6QJª@şuIØµ2//Ş/Ş¦¥‡äÓæ-HƒËÇÒœ¨qÅL±ã¯J]‹éT¥®†±ˆ•~aAAÛŠ—búSÄ|®bÕR=)***""\r" R"***( 98Luşt¬ƒ+UF¢d§JiA)***""\r" R"***(MåŒñÇÖ°úŠ®ceP¯åûş”y~õ` ÆZBŒ*Ô´)M…#½>>ôêP¹ïO›R”„ ‘(©V3Øb—aÏj9‘¢š±)***""\r" R"***(8&FsRì_J_(”ù‘jHŒR…n T‚28ğ§\®dF:sNòıÿ J~ÃNØ¾”ÓhjV>{cÛ“ĞÒ–QŞëë_rŸÏ^ÊÃ:7½iÁRiw'ù™Bir1:L	|÷ü©@?ÅGËıÿ ÖŒZ9ÅŠ1ß4ğsĞšg^ôõ<døQÈC >¦ŒµFWÔR‚˜å¨ä±×­<r3š@ª9Í.Tq‘SÈC¤-™¢—#Öš…‰öL2GCJX¿Ê”*ç®ißJ®B": $àSğ=(ô£•“ì›HëúR1ĞÓÁ½.$ºc $àS†îæ•U}…8ÅO(½›ÉíúQ³ıŸÒ¤ v¢R=“ªØãõà£K@Æy£”=›Ò‚¹ïJqÚ“#ÔQÈÙ›v¥ËãùRSÔ(èÔùtØÃŒğãE=Š÷¤ÊØü(å3p°€àÓÁÈÍ3	ıêUeéüéré¢“#ÔRä†F/eä=~£ğ¥¦.;¶?~G­.R%H)0=) u4d†QŸ±ĞQÖ”mîi~P=hÔNÌAKOÊú
0?»E»éÜe;aõàõ Œüè²%Ó°Ï-½hòÛÖŸE"y¨`}©Ô y¥Ø§¡¦“ƒE?`õ4¶hÔV4!4»¨©©IƒíùÓ¦5W(Ú=)ëŒ|Ø¥ù=¨#Ù±»©§)***""\r" R"***(¦€÷5JÌ~ÄMŸìş”m#¢ş• éÅ(ïLŸdEEHTCF £Pöl•>ğ§àz
0;
V²
(¢‹‰A…S—gÿ ®…v>A¸‚ 4æ 1ùĞ“íF· İƒÔÓ•Ş´¾Xõ4îP½›åŸZpéFO¡¢™>Ì]†‚:Šô¤$w¬.A”Sğ½0)p=å#£®*LAIè(Ô\£TpiÛ©¥ÀÍ;18	è)UC}iÁBô¥ÀŠå ŒƒKä{Ó€:Ó©òØn8ô£Ò¤Àô ('š¸¹Fò3Oü)ŞXõ§¢)íJÄ¸ŒØ}E¨©vz6SJìFDƒ“ŠpPN0)á 4¡WéEÛF0Ã‘Ú“È÷©0}Z]¤ôşt‰ä#cÒ•W{ N>jp‹¦i7aò‘ƒÔÔÏ#l¦—0¹ò8ÇãN1úrÓ4ğ«•.Bq!Ø}E.Ãê*]ƒÔÒˆÏe¡2yYÌñ·ô§l>¢¤	ıê
c §t÷+”aõl>¢Ÿ±½(ØŞ”{¡È0 îhØ{'Òlğ)¦rìoj_-J‘TƒÈ§' §t.Gr1iD8ôüj]ƒŞ“czQÌ‡ÊGåŸjr§wô©p9à<Ğ.B0‡y_J˜*ã¥9cªĞº‹”€B§·éR¢0§ˆ—µH±ãJ®rZ"1œša‰{
œ¡Áª6\r*ÔŠQD~Yö£ËoZ‘@'°Sæ)@£ãŸÒ˜bç «¸ê8¡cR2E5#EWØŞ¢”GÅOåŸîŠQşUIšÄ¬c'®(ŸAS<…4!Ï"©3T†ªñÒ¦y2ÇÆ@¤ÛÎ
Õ¦R‰OSK´zSÙ08ıiõfŠ"R”8æ¤X€Ò²v©HÑ@®SÒ€ƒ©©ü³ıÑG—şÈªS-E‘R€IÀ§´|r1MU ô«M
•ëIRmİÚ—Ë?İ¢z–£6Zæ¤Ø=è^U&Í#1ÔÒ0pjb Œ­4¨Ï"­;ÅHÍ.Ãê)áN8loJÓ˜´†=©Ädb°{Òª(àşµ¢hÚ$[¨¤høÉÅLc ği¥LV¼Ì¢)***""\r" R"***(ƒÖ…Bj,ÿ tP#äsO˜´ìEAu'–s÷E)Bz­VæˆŠ”©'—şÈ¥(1ZEØ´CJ‘‘Rygû¢€‡8ÇiÜ´ìÆ*sNÁëŠ‘cãŸ­.ÃÓm3hHŠ›°úŠ—É?äÓ–1ÜU«XÕ20„õ¥hÁèãSù\ôyìŠw4L¯å{
<¿¥XòÏ÷EYşè¢ãæd+xÍ/‘ïRˆÆ3hØŞ•iÜ¸É¼XïJ#)***""\r" R"***(Ò¥(OU FsÓiš&0'­5¢öüªÈŒÆ?*kF:V™¢‘YPæ‘ŸçSy¨ı)V,pG¢hÖ-XÎÑÍ.Ãê)åè)Bâ¬²=‡ÔSÕsÓ =…=`éTšE)Xƒiô¤ ÷dÇÛm'’}?ZwFªep œ`R˜ñÈ•MäÎ1FÅ¦™jEr™ã•*©éŠœB	È4`Wò«¹´eb5R½h)»š”Gè3Fİ½±T£4C°úŠ6QRàv€íV9‘Œ
\qÒ¤Ú=.ÂGJiØ¥$EM1¹9ÅN#Öåƒßõ«NÅ©¢7¥8ÆOÖ¦X¹ä~tqWrã$È<²zâƒ;
” ïFÃ»Ú‹ÜÙ2 zQS×Ò“Ë?İ«NÈÒ2D]ÿ 
P¥ºT‚0z­/–£§W5ŒÒªW­9TšF1‚?*
…8QAª’cB¨ãáy Pç‘OPÕ¦†›¸Š0)iáW)vÀRæ/˜g—p)vQRõ§ãÑjD2zâ”'ÔÆSôªMš)ùC¸áè3Ràz
‚xWE©Îx§,@ğ)***""\r" R"***(JS• .xQO˜Ö2D~G½2¾õ.Æô¥Ø§½;²Ó!Ú 
R»{T†0>è¥	‘ó
¤Z‘BFivQRˆ× £hb©\ÕMl>¢œ)ø_AJO¥4ÙjI‘à‚œS*U‰Iâ”ÃŒÕ&5+˜Ö‡ÔSöô§ Õ)¦E°ô=(òÏlT»G`((ŒSæ5ŒÑ	Œ¸¥XÀëúTÂ/lÓ¼¤ôª»4ŒĞÅCÜf—gû?¥Jˆ¸êiŞXõ¢ì¿hˆDyì)Dc/’{:QxqëEÙJC3)vQRö¥Ú=*“¹§1Ãê)Ø‚ŸıÑO 5iØÏš¼ßqG›î*ãnóè+ğşCñŸeäOçAJ$Éä~F«ï>‚•'­Œ^Ä±¹}ÿ :7/¿çPäúš2}M.FO±]‰Õ€zœ²0joSN)***""\r" R"***(Á ÑìÈtI|ÃíA”vÇçQdúÑOÙ™ûq'M8Kî*º7;iõ<Œ—E’ù„ôÅ;põ¨2GCJ»=›±e€ùÿ õÓ¼áıãùÔƒ‘A=Í„{o8xşti'ƒš‡zúÒù¸üóOÙ’è–RøRùÇŞ ƒš]ÙêqRàfè¢u—ßó§+ƒÖ««dãÒ¼*9LåEš—û_­DzPX¦—)Ÿ²d»ÿ Úıhßş×ëQo_ZPAäQÊ/fI¼â 2“Î)***""\r" R"***(GE>R}•ÉÃ.:ÒoõO­9[±jj6²$2xıhzœS¹¤)***""\r" R"***(ƒŒæ‡7L“xô4¡ïLÏ4àPŠS?gqÔd”ÒÀ#£ş”r’é±Ù>¦”;
szÓ”“ÔQÊC¦<?­8>)***""\r" R"***(QÑSÈÈtÉUÉ<šváëP«cƒÒŸIÁ’édzÑ“ëQÒ†aĞÒäbt‰·¯­!~x¨”·@:qÅ.R!Í!›æ{šN?¾h õİšvFn•Ç'M9XKR*’yéNØ¾”Ò%Ób‡Éûß•.Ú4Ğ t´¹CÙWÀ#wçFóè) Î(ªQd=[#$ŠPG^µ(b:PâK¦Ñ(p1J`äP>”¬G³d™>´ğÊ{ştÁÒNÌ^ÎC˜ó÷¿*Lÿ ´i	íI½}i¨‡²Ÿöú1¦ï_ZÀ4rÙÉõ4™nÍF3F.VKƒ;
Pş£ò¡SûÂ”ª’)¸ñNWP1Lıİ*ã-ÉÜ“xô4 äf£'õ¦·%ÄZ8ïEdò6;r€@h ƒM"®iõ:±ò)***""\r" R"***(8ns­!$M8¨=EÒVG³Ôj±ÎNiÛÇ¡ (ÏšvÆô¦´ €ƒJ6£4loJUOï
bölPÁºR3<
u!#¡=i=À–4õßÚš?wùÓÔ¸¨1”Ç4Ô 98£ıïÒ¡²1Àœ*E+ĞqQ¨Àëšz3‘HŸgaÿ '½!ÇlÓ¿wGîè"“èhÏµ;÷t „àP>A¹¢•~còšvÅô¥TñK™	ÓAM9[i|¿zU]½ê[¹.˜Ö œŠ“ĞS™wæ…F3Iéˆc‘N 'Kå·çKV¢cÒ¤G¯çJ7„şt’f<ôâ›‡÷üéÔP‰å‡÷üèPùçùÓ¨§på 	8»Ò•£fEî)***""\r" R"***(!›Òœ€ŒäRÒ€SŠÂå 	è(ØŞ”å]´µ7dÙŒØŞ”¡9ğ	äPçš9€@ "ôJAFqšpCÓ¥>a5pÚÇµ>€01J«»½+²ŒŒS*V8ïM##JcQd!HojW$)å03š@›‡=*¹TYIêiêr)Æ :Ñ±‡j¸³NQ(§*xSš&'5ª‘Q‰)'ŠP€sRy-FÀ84ù”FRmô©0àS¼½ËëíTš¹j%r‡<
UFõÅMå³úÑå³úÕs´÷â‚„t©×Š
T¥©jÄeH¤©`Òl_JĞÑXÁ#ŠnÆô©ŠÜR*ò8¦˜ÈÕH<Šu9“û¢“czVÉ””…Aê*UŒàãšFŒ•iš"#•8“kqRydƒŸÊ€„Tš¹ª°ÕZ]‡”&zŠ´Ó4ŠE<(£bö¬d]¬Æu¥(Çµ?ÊÇğş´»[Ò´¹kr0‡<ŠWP@§ìoJP‡¹§}K l‘Å
­¹â¥hÀ9"…AŸ”U¦ZQ©|¿z~Æô¥òıëX³E±Æ=©Á9¥ ´V‘ÜÑ$  0(¥
M/—ïUt\F€IÀ§ñÆiÂ29—czS½‹BS¶Q@BzÓ©ŞÆ—c
3IR”ÍéT™JâQNTÉçò§³ü5IØ´ìGJš•şÏëJ## ªRW-1¨ÎiI<T…QI±½+K¢Ó ƒN
HÍ(AE8!Çšf‰ŒØŞ”à£Š~Ã´Ú»¾†‰±Bp)Fñÿ ×¥Râ–©6h˜QEf‹qîšeH@<BƒµTM.„N¿…+‚qŠvœæµj¢ĞÔg"†\óšvÖi|¿z¤Íˆ„‚8"€¤äR˜9&”DCUÍcE+lóNQŠBO Ğ§µR‘JwEHpÆ)D)ÜSæFªHh!‡…[Ôš‘aşé¤(sÅZ‘i‘²J˜Æ;O,“È§ÌTÈ€$àS•~aOò”r´ª‡?0­9•“±}(Ø¾•&Åô§AëG2-I{Ñ³w8ıjqn ùiDG¸£›BÔìB«È¥*3÷iæ1œt¥dtÍRfŠ Á€0)@òqOò‡aúÑå³úÕÜµ0QÆ2)B7§ë@FéŠ'÷¸¤Z£
·cšM­éSl^Â%ª¹‹æ"U9äS„}À©<¯öZ_,ãÔù—B£"3=E&Í½ªBzŠ¨¡6j¦F=)Ddõâ¤‘ĞRªxU¦îZ™”?¼i
‚¦Ø¾”†0{Õ¦Ñ|äAvıiBrqíRˆI6ÁjCS";óNò³ü?­<FANÃ §{–ª1_½/”şµ&ÅÏOÖ±½)İš*„&"94Ò¸«ÒÅ“’´ùŠU\N.Æô©š!Üb“Ë÷ªLµ4F ƒÈ§'¥<Bsœfœ#Æ{SNÅªƒËÕqNÈ=)***""\r" R"***(=cp3J"çîÕ\ÑT	)ÊàğzÒ˜‡ašQ÷¦kˆLœÑŠxAEÓõ ®q 7÷EH6÷4aĞSœŠ¤í¸ÔÏ–¼Ïj7ƒÁÎ½ŒïWãÜ‡çÈvÑÙ¨GŞœ“NâB]w“ÑiA'¨Å"©ê¥»šN${1èÎE=zcv*5)***""\r" R"***(ØŠx<tr‰ÓĞR <ÒQE.TK¦(r1Îiàî¨éCÅ.^ÆnÇĞg¥0»Q½½i¨6%D”±ìß¥B4â¤œï.:CÙ»“I¹}i›÷Å rVR@Ş†”15sØzTÆj\LİJw§+cŒTY#ÿ ¯NLvÍ.Te*^DÔS2@àÒTr6G±¹%&G¿åL§*)***""\r" R"***(>F‰ö³ŸZ(¦’sÃŠ9lO²°êrzšh¥?bÑb1iw1ã4”„ŒpÂ“H—E@lôÜ·÷Å(<u….Tfè1Şhşé¥ßøü)´š|·#Ù1áóÚœv8ü* 3Ş¤´œLåI¡w·­9[pÎ*>3F©£•™ºD´›”w¦'øéÁ95)***""\r" R"***(\NšB†¡§«LÔ{©¥ÁÍ.VK§rPGqJXôİŸÂš¡ú)***""\r" R"***(.·çSb6¨úÓÂ€r3×õ§/ÿ ¯JÄû&8uÎqNİşßéM¢©"}‹lzœñ»?…-GNPİGëMÄ=‡€SŠ0¿Şı))¥˜zR³¤Çá½úQ…ş÷éLŞ}(`G$QÊÉöcóãı(İşßéM¢ƒÙšQôÍ53M8)n”íb]$/îéf8ëC.:‘IBLFQJªIö¦€§®)ã§ZMƒÔĞ	¨z“ìÉıÜRÓvxoÎz)4K¤„ ¢œ¨1Á¤#Å=:Tò™:by~ôà01Eíb];R…-Ò™<€¼Sè¢–ÌŠ(¦G+ÁÈ§+œüÆ!#4‡ƒŠarÜ~Gù¹Í0g9åİüT_Ry´ddf—kuÅ â8¡µ`ä1–– Êi@?Z‚ÃÒc‘B‚K‚z
‚\ )5%Ğ})B“Aƒèi0}*J(" ƒN
3À (ÎE=œæ“%ÀLCJ€ƒÈ§íÿ h~t¡=M@¹Ú ' §ì¦€¡zPŒn¡¤©)
s@{1”£xô¥òÖœ“¹.Í¬OJ_/ŞŸå“ÑèòÛûÔ®ÅìÆŒ§4ìCKå“Ğ~´ê›‰À`S”í‹éJ98§ùcŞ‹’à1TgåûÓ–2NFGÖ°úŠ|ä¸ù~ô¡ ëO	êiv
\è\ƒ ' ¥HÍIå‘ÈÇáIJ÷&HDE-*…#“K±}i]\ÉÄTû¢–€¤¥Áô5W+€H”!?ızzÅíùÒm•	±}(`HcÀÏ4Ò¤Pše%©SE P@©Y	ã‚İ«M¨Œ “OZpÈ§y^ÆŸ1j(bõÅ(ô ‡?ız_/+HÈµjGƒèi¬™9&¦Áô4ÆBNj¹™Ij0(£Ş"ïƒG—şÉ«LÕE£Ò¤òÇ÷M8GÀæ«™•ÊD¼R2œŠœ(´…;Ñ”JÆ>:ÑƒèjcÏ+ØÖÉ£E)***""\r" R"***(§ĞÒàú›Êö4y^Æ©4Šåh„)')Â?Æ¤ò½(B½«RˆÂc¢šGByö©¶C'$ÑH¤™ RNı(ØsÖ¦{<¯cT¤kˆJ8æ§Ò¦òøÆÓG•ìjÔ±»Kåîš“k€´ıƒÔÖ©¢“¹¡£ĞÔ…x"“ĞşU¢i”†maÚŒCR`úL7¥4ËW#+¢€ HP Ğ# äZ&h3kÔ'¯*®zæ”ÄzV¤\[D& NI¤1Ğf¦òñ÷¨)èkE&Zz‘"v#Š
œ*_-JQ)***""\r" R"***(RfŠÄK»¦qøS€8éOò½(R0i¦6Èğ})Jxæ¤Oÿ ^”ÇŒäjM—©¥'Rì9Á Bs‘Z&lšcqÎiÔág‘Kå{´Ê²‚z
\CR*àÔíƒÔÓº„ÇZ*g‹Ûµ0EÏCZ-ŠLe=>è§³éJ±Çj¤ìÍ"ĞIè)<¯öZ”F@â—aõ­99¬Cåîš6ŸCSl>´¢ÿ õê“‘—ïG—ïRyL4ykWÌj›#òıéNy0@)***""\r" R"***(8&î«R-H‡búR… ğ*_ xĞ!
x4ù‘jhĞÒ˜ñÎJ”D{ƒKåàt¦Íc2CIßı*,{ÓZ,Ó/˜j}ÑM äñR› 4¡By«M¤EƒèiëĞ})şX=3G”{L´Æ`¢UqÀ§'Úå{iØÑH‡ĞÑƒèja=)***""\r" R"***(?aõù‹SE`¤œb—Ë÷©Ìyÿ :O zš‘JdI?zŸå“Ğş• ˆôå\tÍÚ–¦3a æ§Ò¤O4"´º.3#)•9… R 5(F4»¨¢÷6ŒÑ\õÏåKåûÔ¢<Œó@W3)M)***""\r" R"***(TàsÛÒƒëN1NT ğ)¦R™ÇüºÓNà@Î
œ¡é¦<öüª“5SE?Êö4yxõªE*ˆa õ¤Ú¾•'•ìh»OãWvZ› 4å\õñ)***""\r" R"***(8BÀsV¤Zˆö/¥èµ Œ÷œ#=@ÅW1JdAHàKåîÔ¢2zKåzƒEõ.3D>JÒˆ‰èjQ}i|z¤Ëçµ³ŒR”ÀÎjQ<ÒßÒ©2•DCGĞT†,”¢":b¨¯hˆ°GQIµOjœDÇ“Ò—Éİ?•ZØj¢ 
àS•sÔT¢)ÂzS.5@ ¥©LXààQå})¦jª"**C8ÇåJ"#Tš5B §°¥{Ô¢<qš<¿z­Uª’0;Rà«š]ƒÖ·J«T¹ò^óè(óµG¹½i2}kòCæ½‡‘(›ÇçNY½ê
Uë‘×Ş“.‡ra 'Å9d=ØşuÇL~4Îy£Ù¦dèLş½H®@ªhùïùÔÈÇ:N™.‰+H}ZO7ÜÓ>næƒÕ>Íìÿ 3'©üéw^MFsÚŒ·f£Ù¡ª,6z·ëNÿ x~5sßìñœQËfC Ç‚sÔSŒ™=*¾)ÅN~èü(q!Ñhzœwæ‚NO?•G¸ƒ×ó ¹5.&n‘ b)DÏéQ©9êiN{T¸6fé"Uô­=_Ôâ Šz÷¨pÔÉÑ&ó29Å&ÿ ö¿Zb’3Alõ¦r¦Hş½9]‰Æj%-89§ÊgÈÉ2}hÜ=i¡˜â{Rå!Àx<ç4õ|òJˆ!ÆCS#½KŠ#Ù"BO­ npJ0ÇƒŠ6ãøGçSÊK¤Å£èi>lôô dâ—)>ÉõŸïS‘¹äÒaÎ(BIëùÓåfN›zp'~´ÚpBzñO”‰SĞBÄğE9HÇ_ÎšPçŠP©ildéÜvG­»ıi»[û¢•TuÇ5¬^ÈpÜÇH¼* qŞ¤ŒÒqlŸb?æïŠZfÆ¥ÙƒÁ©å%Ò°êÁÈ¤
AÎêZ9EìÇoõ¡Á¦QNÈ+’Q’:fãëI“ê:\¤:M†"‚I94Ğ~´sê?*V#Ù‹ŸZ2=iB±£czP•ÅìÀ9¡ıE*‚)***""\r" R"***(-]…ÈÅR;æ¤VÇJ`LŒæ•T¯F©±.ÄÒŒÒ•o­¯>µD{4 œ
T?0àŸ6E;aïÅKjÄ:bQNòıèòıê9‘Œm=X·ZO/Ş”:œÒz‰ÁØZ7cß­…Tœ‘JÌf89Å‰4>QOPB€ià"€Kıj@ª ù±øÓiÊø"{4; ô4ß•çƒA'Ó=HtÂŠN}J^}GåT/f ¿ZZ $â€Jš‡¡.‡'Zu"±'Ÿ~)ÉaTÔÒjUPÙÈ¥òıè€À  àæåûÓ€ÀÅ{1äfª¤dm*MK%À}=´ÁÈÍ(~íH½˜ú( rhfä#8É  Ï”FGÍI´C€´¡ˆ¤¢¦èQw·µ.ñéM¥UÈæ¥‹]çĞQ¼ú
<¿zRƒµ.d€§#4¸' ¡Q±Å=r­+±8Ãz]ÏıßÒJ=+²yD§”€ƒÓ4µ-’â @iÉ÷… 8§„ÁÎj[!ÄZ(ëÒŠWDr°¢ŠU]İèĞVb¡<óJT’iUq£ëE&ÈqW`õ4åŒà`ĞN)ê‡TóXN(@0 § IÀ§€T`Š)ó\†ÄØ=M8g ã½(LŒæOšÄX¡úTg§ãRìcÚšÑóÈü)©"–ã)Sï
w”O")ÍW1¢ÜZ	©¥M/–=i¦h•ÆÒ” f¤D8â†LtªR4Š"¤(	É§¸9È¤U,2Mh™I+ˆ(§y~ôy~õiÜ´Ú2CJTŠERFjÑ2Ò¸m,(©“ĞPAš¤Ò.(Š“­pj“¹¡ ô¥ØŞ•IØvd`p)BzšxBO4¾_½R–£å"|€)*R‡µÒµNå$ENTfŸ±½)B`e¿*i±¤È™qÍH©Œ|tÅ7czV©–ˆ¨©„d÷¥01ïZ)!¦FËsMØÕ/—ïúPS9«M£DÙ)***""\r" R"***(ò œšG¨éV›-¢«´ç4à„Õ©jhÈÕCu© $éKåûÓ„ez
Ñ1«‘˜É9 Ó1ÍOÖ†¹_1JäI÷iiâ"yëK´¨éT™¢l`ô§l¦–…è>•\Æ‰òÇ©¥<Œ
”ò)***""\r" R"***(3czU§b“±USiû½(Œ“€j¹‘¢	¤<T«ùÒ”8â­2“¹)***""\r" R"***(ö\ñéIåûÕ­Æ7'ÖŠ“ÊàäS
Õ¬Z±ka)é÷E CÜÓ•OATRvaE)R:ŠJ¤ÍT‚¤¦ù~ôê¢€ò1M1ñÅ:ŒŸZ®b¹†r¦•\“Šu(Ry©2Ó°”´tâ€	éM»”š‡®M:£Æ*J¥±´Zı
mIE_1¢v#£­H'ƒ=¨æ1ã¡© úR„`1ŠQi©$h¤ƒj{õ§Qä‘ïAu¢÷-4QJšcºBR¨àšP˜9Í:šva¥=)***""\r" R"***(*©^´½ñEY¤$ÔQN
Hù¨òıêÓº5RE;Ë÷¥“È5IØ¥1¡ˆà
x”áÓ€ÀÅ>aóØŞÔà t©iB1ã®Ë»#qØøSvóÅM±éHÃ#ü*”‹S#£ õÿ $A£Êe9«‹)ITçŠpOSùSÔn8Í(Aj¹¬ÍØÍƒÔÒÓÄDô4¡
u­"ÍÈéÊ™4êU\Œæ©È®a»©¥
qĞÓ¶{ÓÂ0*“•ˆÂ’qNØ=M)u§ÈÎjÓ-Lg—y¥*HÆ)***""\r" R"***(IE2”Ù•ìhØ=MKEZùÙ¯ğŠvÃê)Àg¥)VEUÚ)L`OSK°zšZU]İé§Ô®v0©íÏÖšG¨©ŠÔÓ=Wõ§t\fÈÎ{S•AÍ=b^¤RùcSOSUU"2„ñÅ¨©<¿z<¿z´_´"À)***""\r" R"***(úS€¡§loJP‡¿H¥PøğÌHÁgû4ÍßJ^M~jàG²°ñ'áNY	äÔ[[ßò§(aô¨q¤É<Ïöi˜Ÿ_jJ(Q!Ñ¹(b;Ôˆã
	=M<ƒÅ$J‹D¾gµgµBF>´õÎ99¥ÊŒ1şgµ8KÇZ”!#4r¡{;’«“ÏZuD ¯ ŸÎœô-úVn"öL˜>iON•8ç#ñ¥cÏ Š9H•6)cŸOjààÖ›GĞRåF.á&)***""\r" R"***(8JO©I=(òÏ­.C9RDÊÙàŠ_¥F ô#?J~G¿åPâbézirßİıiëúSªyLİ=Å(fõ¤£ñ§Êˆt‡	2:R‚O8ıi¡XŒ‚?r®sRãb!ÁBØü)õ:
x\tÍM™›¤…¢—aõ"‘ÈT=ïÃğİJŒnîş”àsÛ­©.˜§š#¡¢ŠfnÇ+1íšx8{ô¦)>ß…?kc¥KD:MæşõÛÖ“ĞÑƒèiYé¡êXõ-0Ïœ3š‹24-(bz·éM vQF¥·'Ù’÷¥.sÅ4(3NòÛ³TÙé
“‚ß¥:˜#=Í.ÁêjZ±>ÉÉ#P(©%Óh(£h=ô£gû?¥=	äb‚GCNSùü)ª™ÎE;`Í&¹§+Á¤U$u§ÀÁ ÔØf( ò( —ĞÓå³ Ç»~”ú@ƒÔŠ‡¸Í&’%Ó“Ò€{S°GQA ŒFn›æ{R«ç¡Åxæ”'?w…&®C¦.öõ 9Ï4l`)0ÿ İ¥b9GyÔ¡èiw-)U=¨±.Ğ	"›°ƒiFîø¡¢‡ì:p ò*1»²ÓÕqÉëŞ¡¢}˜µ 9¨ÁÇztÍEˆtØª@ê)Ì¹äR"õÈ§íaÚ‘." ´T…}Wô¤	À¯¡#Sï
}(‹qøRì¦¤ÉÁ§GŞ” œ«˜ 94>ôê<Ò•#µC±<ŒJ)p})***""\r" R"***(	¡;J#¥;aõ¡F1·ô¡²¥]ßÃøÒˆØô§…'µ"9”¡ˆ§|¾Ÿ¥/÷JÌ9 04õİ€GåMP	À¥9UëA.˜98äSjCâ“åşïéRİˆöbGŞ sB*œñODëƒIî'¾_½_½I°úŠB¤v¡6'1ÈjpÎ94åBiâ.:Æ†KÆÈÎjEÏj<±ëRøÔ²yÓŠÆ—héŠ~Ãê+)àGåûĞªAÉò„P“Ò•Ù.QNAçìAHÍÆÄtª»»Óğ=(CØbô±-)***""\r" R"***(UÛŞ—Ú°úŠU\j[D¸&7czSâ`r GJpÒ³r!Ä(§¢†QNò½…EìÌÜF*g“R#ªş´ÉëúTª‡¸Í7"\n0ò•u©È;zS
ëúU)	":)år0Íhš5Q:şêQ	 Òª`óL¤¬zNx"¹2däb®-šÅ&BÑ3Òˆ&¬*à`HÉ“Ú´ŒË²!
§û?¥?Ùı+X´5HJdç4»Ò¥XNE/•ì*îl–ƒ<¿Ò/Ş¤XÉ<ş”ó	
Ñ;”•ˆ<¿z
`g59‹ƒğ¦‰è*“Z‘'Şúw’ßİı(òŸÒŸ1ch©.z~t¾W°¡;”’#UİŞ†N3RùDvÆO\VÊNÅQRù^Â+ØV€EE9¢ç¥8 (Er‘Ô‡iB3J#'¯éZ-•ˆH#‚)¬•a¡9éHa8åEh¤4Ú+ƒƒJN*³çµØ+HÉt@Ë´g4¨9Çj—ÉÈéúP±°äÒ´M\¥a”à„õâ#Ïl~ã)***""\r" R"***(Uõ-y~ôy~ôò¤P«¸g5I³DÈÈÁÅ(LŒæcúRˆ›°­ïfGåûÑåûÔ‚&î)â2ª½ŠNä=éÕ1…QHbÈè)§sDîDO¥ï)ázv§l?Ü¢H½ş´´ò™ê¸ &Ó’8÷­ÃˆÊ*@ºKå{
´ÕQŒHË¸ç50Œ˜£ÊñùV‘‘]4+”=©Ê5#D{
O)ı+E$Æ¼ÆĞ=*@„Wô£iôª4º°ß/ŞŒñOUÈû¿¥;ÊöîÇBÑã§åM
sŠ°ÑäSx?ãT®h†ÁÎiÁIçµ?ĞR…' ¦U×B6]£9¤©LdõÅ<vˆ©Uww©yşùRùL:
Ö2ĞÑ2?/Ş/Ş¤ò›¸¥1ÀÕ]˜À01EHÊş”¢<ŒàT·rÓ" • àRùdtÅ<(ÇOÒ…¹dtï/Ş"=p?*_)…i{¤GåûÒaÚ¥Ø}E¨£™•ÎCJ£qÆjO/¶åG–GLU¦ÇÌ†‰<_%ªTŒçJSzŠ®b”ˆö7¥Xv©UvıêxŒ>k!©=Í9PãŠ—Êöl#Š\×/šÃW8æ#9¥T8åJpF5\Ö+!¢#Üf¤*†Àâ°zšw¸ÕA‡¯µ7iÎ)***""\r" R"***(NTô"ÄT§ÌZ‘—ïJôÏ•/•1Š<œr9ªR+ä^Xn ¥X™NjM¸íŠP¤Ö—¹¢™Æô¥O^*UR½iDaù'IØµ2‡<Pç•©š¢<éV¤_?b5€ášRÆ¤÷À¥òò=ê“¸)2Å/’İ0?*QÇİ?•h¥bÔÆ*ã½;czSÅ¹'­;Êj®fR‘Æô¥òıêA’)Ø‚š‘JDA9¦´y÷©ü½İ4Äş•i±óÊœšr®îõ/”OŞ¢Øb©2ã2//Ş/Ş¦0âšcÇÿ ^™ª’d~_½9GğŠvÃê)Ê„”ÊRC#“M(J›fGøÑåû
¥±\Ö òıéÕ0‡#%!Käƒü&´‹-Lø¬¸÷¤2r*6|ô¤;¿ZøSŞt	DÄ÷ü9d$ğOãP)***""\r" R"***(Àğ?Jr“ŒšC7D›Í÷y„ôÅEJ­´óKÙ‹Ø“£0êAúSÃÇ][##"¬p@¡ÀÍĞd¥ıOëNW8â ŞŞ”ªüuÇãK‘™:ÛÚ²|½ª¾ãëK½½i8XŸbXŞO"”H=*/NiÛÇ¥.B]"q.O8¥2qŸÆ §½.ãêjyİ"_3·¢BjyÎsNV'Ò—"2tŸBa/=:_0˜ü* 	è(äsÒ—%ŒåH$ àãñ§¬€ŠI=H¥‚¥ÄÉÑE…m83ü_­B²Âç<~´¹tI·ÿ µúÒï=ÿ •B¶?*p$µ<¨‡Deã¨¥ŞsšˆsÁ§ƒÆ‹#'D˜KÓ¥8HïPâ;şu(ÉÑ&ó}Å&ÿ ö¿ZŠ\„{Mßí~´¡ˆ9ÍENRz?:>ÊÃ÷ŸAJ¬IÁ¦Ò©=@ı*HtÚ%QùS–_Î¡ÏaJ7*lC¥r_8ç§ãFâNAüE¸0qíJöÍ¦N“$Éõ4»Ú¢Éõ4¹lg&Ÿ*%Ò&Zrç±@³Ô~4ğç§•™ºDêqÚ¼z…\ä}iÅÈô¥ÊG³d›Ç¡£xô5óè)U‰ô©qM’†–£Sƒšvñèj[³¸áÙ§)#¨4ÀÙä\ŸSK”‡I\~ïöOåKzfX÷4™#¡§b]4LÓò¥Ş3P‡=?=r}èåD{2@OcJvæš¹Ç"œ¤ƒÁ'9õ<g²ÇÊP¤ô5Fny'©4Á8¦İó@8íE‘JŠnñèh)***""\r" R"***(Æ &…lšJT Er¦‡ä†œ§=@¦è)Èê)37LR€Òô4êP¤ò*Y°èiÃ=éÛ¨¦GQHF ãµH:Tu"ôJâ9_iù>¦˜«×+úSö‡c' Éõ4!ç VŸéStŒÜŠ(¨z“ËaAÇaJ¬;àR'µ9Wq@¹_4¦R¤Ğ~T`zP'Â@G?¥8ŒÔx § <ñRâ„à8v§€1œP )jLÜ[ c¥9r4ÔM9K‚‚yàz
0=šÌ@Àô¢+nëÅ9T“Òr‰J€ÈíOÚ=(ÀëŠ–Ó#bªç¦)v0èi1èjLCSr9Í¯ıïÖœ3Ü
\C@BhºKŠ¤áı)Ùã¤QŠ\J‹á`© úS #øJxéH\¤˜”i 8ïùÓ«;³'&ñèh	Æ(*j r(%ÄZP	8$ô¥U æ‡¡”¢
¸<Ó©Py©ø‚¡³7¡‡B?JUÚÃ;hÚ¾‚”/ ©{.€;S¹Å
8ä~”õBG)***""\r" R"***(â*©ûÃáœsJ±)|¶=*3q@ÇJ‘‡jj¡éS*•ëRÙ„l¼—ô¦`1úU†RF¦ì8ÇJCP"UÁû¿¥?ĞR” f“óŠ´ËQAF ¢ŠÒ2(R©¨¤¥Mh¥râˆ'INØ}E*¨‘V¤h’oJkzw§“ASĞÒ´‹)! Ràz
1ÒŠÑ;–•ÀqÒ¤ ¢›°úŠuj™aè(ÀôQM;	«† £ĞQEUĞ%`Àô`zR…'µ*¦:€i¢’li£ó¦0¸+‚Oµ7nz¯éW$ZB.É—ĞR„8àb—aõ|Ã±Œ“Ú“Êö0P Ràz
|ã¹Q”¸ ©6ƒÑJS°«R‰è)
‚8”‚:Š*Ó(aB£µ.Î”ãôØ
Ö/Qõ!uãîÒ`ú™ÇôÜCZ¦iHÔÔfŸIµz€)ÅHíUÌÍTn1“' ¤òÈéŠ)=)Ê¸Š¥)"­b0 @¥ÁÆqR`z
0:b´Œ†ˆéA#¥)C1FÃê*ù‘I!Ô`zQ‚z
#¨«R.!è(ÀôPN*”Š¨ãùPÊãñ0yªŒŠ‰B½åJ€äT¬¹éŠo–GLV©š&&LS x©BzÒyJÑ5bÓ"§¨zS¼¯aG–}©óšb`z
0=;gy£aõ¢jÃ€:
;¾´í‡ÔP#'¯éM444‚:Š0jQF¥ksDÈöîş”T˜”…AíJå]¢°ö4l>¢©60\7P?*u"©^´ı‡ÔS¾¥­†ÑJA’˜Ç)^„Q³¸"…BiÁHÁ¡H´ì4!”à è)àr)BËúV‰—Ì"zRœ‘N€9ı(1xıi§a©ì9É§`z
R„P“Ò©;”¤„ ‚ŒAN‘ÉS°=Rv)IÓ—)***""\r" R"***(ÔÊè(ĞSæ`tÅ©È¤ç+NÙşÏéG0ÔÆ*“ÎiBÔøSÂp1Jç­Re{@Ult(ROAøS•:ştåRM;‡8Xƒñ§*©íùR„$fœˆÃµ.k-
SÇè:BŠ”§¡£aïMJåóÑÏ@*S=¿<£Ôb­¤E´ÿ wô¥
Oj•PƒÎ)vJÑH®r0=T~ª•H7@(ØW·åUÌZ›#¥ Š~  /Ò­Hµ6"·¥.¥(CJxN:gğªM¤ˆéCzùSöJ0=Zes)***""\r" R"***(§ÚKå{
Qg‘VŠRHB¿¥JS?ÃúRy^Æ´M)***""\r" R"***(NÄa8–œb1øQ°úŠ¤ĞùÄ;­8mnƒô¦”a@V=8¦R•Åq”Æ`8"¤(Oß¤1ƒÓõ«[ÆDaö§v¥ò½…Yö¦R˜¡”E“û¿¥(ëG•ìj•‹ö€Oµ(8?ãMòšŸƒèjÖå)3á¿4ÙúS¼À=jÌ3FóŞ¾?Ù#ô`N&ÉëùÒ‰3Ö¡SÔääÒtŒåE"MçĞS•‰ëŠfí¼æ…q’zÖnbJ­Šr¸ìj-şß­;ñ¨ädJŠ$ÜO|ÑLŒRïã¥.S'E@Æ)KñÅF<cõ§‘ÈÅnˆàçĞSÕ±Î?ZŠœ$ö©äfn“$Ş)ÛÏcúÔ@†èiÁXâ—!›¤‰7ÿ ®œÜÊ£÷_Öœ§*\‘:ÉÎÉíLVÇœ\v¨ä¹Œ©
ƒÀ¥ó	éŠa'¯JPIíÆ“›¥bPHéE"œ¹ü)jL-G+(éN<Šb¶8Å<g¸©å'Ø1Í8?£Ttª2zf—).‰ ƒÈ©|ÃÜT#¥9YjNnŠ$2ñ@vëŠm­CV2tPğÀğ)AÁÍ7wû¥*œ¹¥c7E\£õ§:ùÔ`‘Òœ¯¦¥¢=“CÃ°¥zŠ` ô4´¹It¼…gÈ$R‚çi8=?*2W88ö¥Êe*H\¿¥.ñĞÓw·­s‘‘EŒİ+üãO^)ƒÒœ¥±Ò—)›¦Jÿ -0}3O©³3tÂ€psE¬CƒC„„u¥¦˜N.Æô¥dO(ğÃµ(qü_Î˜«sÚ€¢“ˆœîG?úşt ĞRìoJ†Œİ1  ÿ õéÊÀ`)¤`àÒ…')r’àIæZp`x¨Ô0iÊ@4¬fàJ»ñÚ‡¦«®=©Ê»»Ô´K¦8°èr)¥@ïúT…Xv¤ñJÄ:HfÆô§.áÁíéAVâ¡“ìĞ”äëĞt¤@	äSÕ9ùEK!Ó HèjNiªŸŞïz–fé¡€àƒJ­‘Á4‘ƒ@ t¡$C¦…ÙëùÓ€Ü>aL§)lqÈ¤Ñ˜»Ò—¥ úŠpõ\úTàÇRäúšJ]éPCˆn#½/˜{ŠB¤‘IJÈ—?Ìôo†š£'‘NØ¾”¬ˆtĞ¢C)***""\r" R"***(9lá³HŠ¹éOTşèª²'Ù¤<.3ÏZBƒµ8ƒŒâŒÔY²loJräih8¤îO õ9¥¤#4í¬{TØ‡Š7À§†+Òt§ì_J›È-“Š]éFÖª5'”6·jrïšüóJ<
—±<–
U hØŞ”ª¤E@5 ¡@è)èIëB zŠz®îõ,‡%¥jUN>aRC‹Cié÷EÒ” 8$ÂHéL© úTÈ‹11éŸÎ—'ĞĞ4â„‘4†N)ÁH Ó€¥ p)]´ª<Ò¬d*pŒƒµ‘”£qĞS€'¥*©‘O ‚§™éŒlÒ:
‘bÈéš_+ÃúÔ¶¶€È©SîÒ*qó
z§=8¬Û1šT’)BĞS•84à Vm™ò°UéOUÁÉü(	‘œÓö7¥O1-)***""\r" R"***(*	ÉŒ£¥Ø¾”Œ .@ªZD;wqŠ6•8§àg8¥ÚXtâ´Œ†‘&Gõ¤òÏ¡üê+ıŸÖƒ•­¬]‘ÇÙ§ªxS•?º?Z]éV¤RCv/¥5€)***""\r" R"***(Š“czQ°ã?¥RÔF¨ qKK±½(ØŞ•¬dh•„ ´›Ò¤¦—Êÿ gõ­‘C
°Å%L¼R4|ç«R°QRÉ9+G•şÏëZ)¢ÒD`dàS‚sÍ=PƒÈâ±})ó"¬¬0ÀQO
ÈlSÚ­IˆúœRà{ştöˆi»Ò¬¥k	ïùĞ åN>aK±})ŒEU#8¥Ø¾”¡N8RìoJ¥`°€ĞQKµ½)Ddõ«Aa¦2y"“júT¬cµ3czV‘¹J7±}(
ANØŞ”G&­7r’hc€qŞ›RmİÆ(1’0V´ORâˆÖ1œ¨§2g ©R2zŠSVµOShî@## ¥TÄ*]‹éFÅôª¹Nä{Ò‹éRl_JQ# ~µI‹^Ä[Ò«éRù_ìş´É¯ëT†›" /½)Œ«úÔWû?­.ÆôªM£DDb’¿­ U TÅH"šT’*Ô†5[1SĞR²qòŠ~aV˜Öâ óNØ¾” ¥­¹ªbl_J6/¥8.sHAjÓØM‹éFÅô¥¢´MM‹éFÅô¥¢©-„Ø¾” ĞR…'¥<DGQšÑ;)***""\r" R"***(˜ÉäŠM«éSb0E'•è¿­]Ê»"Ú¾”€*_+ıŸÖ+ıŸÖ‹Œ…cå*óó
›Êÿ gõ£Êÿ gõ¦˜Ó±Œ‹J÷©dtª¿ŞIš)˜Éê¿­,…ıj}‹éFÅô§v>dFª$sN
O S¶/¥9cÂã5I¡ó"=éK°S¸û´ğ‹EÌNdK=©J‚y0Œ‹úÓ¶/¥h¥ ÔÊûÒ€€œS²
hˆƒ¿­4ÊS#*@Æ8¤Ø¾•0SE;búUs¤ŠûÒœŠ¸Æ*m‹éJ±«~œŠçDj§QK±½*`€u£búS»1®"ª{T›Ò‹éT˜¹†  À¥M<FÈ­(V^‚¯›A©¶Šr3‘KN@QJå)ëJQQNØéKBfŠc
ôúÒcëùÔ˜'Ö“ÊbrkTËçC0=ÿ :T<ÿ :•şÏëJô<U&>d  tu§‰èi|­¿xV‰–ª"=‹éJaOØ¾”Áè?Z«®…ªŒF9´¡à
Pƒi¦‹S#(ç±4¡9(›TóŠ¥"ÔÆT””íéWvZ˜”RìoJ67¥\Xœ˜Í&Åô§„9äqK±}+D.{”)ú¯Ò¥
Èµi—„dÁ¤Ø¾•6Àüã†ØU&hªl_J6/¥HalñJ"=Å4ì>r:)æÚÆÀãw¹JLo4¡XëN1È§loJ¤ÍcQØø3Ï>‡ò¥×ùT$äò?*]ê{~uóÜ§ëî‰*¸)***""\r" R"***(ŒSÖQ•G¯ëJ.&r£¡gÎÏqJ$>•]H8ÆiáˆéRâŒ$N<ÓÃõ cÛ"œEdâfé²C Ï4»Ç~*-ãĞÓƒŒvüh²3t™"Éü!©ÂCEBH<€?
z‘´œQ›¦Çjr¶îÕG¨ àÔ¸™º%ÀäS‹ûT#9Éı)Şbú‡'IŞi|ÃE08'µD:H™$éK¹}j}?Zp'8+øÔ¸™º(™“OªaŒrIéPâe*l˜8ïÅ.õõ¨„œdŠ7CQÊgìÉw¯­9_ıjÀÒŒgš|—¤‰¼ÁŠPùíQ©'éNSƒÀ¨å3t»†5>6^Æ¢¥CŒñùT¸™ºE‚çš@ÙäQÒ‚	É•fâfé¢]ùö¥Ü¿Ş¦dzÑŒñSÈgìÇÉÆM81 ŸÊ˜«ÎÀ¥ÚAÊŸÎ¥ÃR$‰‡½9\ŒœT@ç±§®yÛúÒå3•?!CƒÉâ•d€E3?vœ¡zcó¡Å:CÃ¶zR†™€HÍ.vŒñøÒå3•!ãÔğ8â¢è)***""\r" R"***(<9ÇJ\¦N“$ŞŞ´âıÀÈõ¨Ñ‰ê)Ùò?*—C¦=Xu—yôÀ œñøSªZ3t®Ço>”,qÍ R{Q°úŠ—ÉöCÁ#½89E1PƒK´÷SR×A:H™Í¹á© ã°¥;¨ü©$fé\77\äSÁÈäR)‘KPC¦…@ëJÔ*2M.Áêjt#Ù!T¤TÈ@¨vŸCRqšmé’ïoZPçÆ›GNÕ!Ó½}iAdTdäÒ¯Qµ<¤¸è>€HéH‚)jZ3tÇ‚OQŠz•’:
p9ìi4Œİ1ÌA<RQHKÜRåF|‚Ó×•à‘LêE8 T´C‹¼ÓÕÉ4ªêk6‘.Û°ìÔ&{R”SPÑœ 4¹ÿ !Fö<şTíƒÔĞ‘Eˆä' ‘O]§Œ~´Šyà ŠD¸
`*JbîÏğõı('’¨4*•êik=‰”›©¥Q‚z
ÜXzzF @G9¥
È§¥ˆq¸õcéš‘ <šÈ©•qÓ5‡0¢ÈJnÒ)***""\r" R"***(fßc7 84à¡y  ŒÓ‚Põ-ÄÎiTy £şµ*Œ‡ñ©°œa{T‹·-5Ôr21PØrh%¸>†‡ÅCv!Ã@\ƒ´ìnĞ¿v¨ÍKfN6SOğ9¥Ø)zT·byG§çNØ(TçŠ—ĞT6g(²0 ª89§m” äJè‡Pš~ÁêiqƒƒOÁô5v°"ƒÇµ;búSFàréNœäT´ÅaiÊ ŒšE9T=ê["QB æ¨É¥òÁéšP¤`ÖmêdãvOlşTğp çò¡~í< #5˜8€@FjD iªLT
ô¥ÜÆHiA‚E4©#5>Áêi6zjD$ˆ<¯cNHÈ=*_,zÑ±}kE$W(ÍƒÔÑ°zš“`õ4Ö\tI…˜ÑÏ4² Î*LĞPWÔV‘f‘‰Å>´»©§2x`úÑ;Ê7bûÓÕm ROJz©¥i16SFÁêiØ>†” #<Õ&4ÆˆÊö4Ï$”!4=1ùV‰•nä;©£bÔ†>;ş4İ­œU&4†lQëFÅ>´í„ŸO¡«¹Vº`õ4äAF¡§F§*Óš)***""\r" R"***(£Å1Ğf¦UÏ\Ò2€qZFLd>X=3@85(‚—ĞÖ‹b¬0 #œÑ±}éø>†€­ÿ ëªLi*PŠhqĞÓ‚’p*“(—"šTMX1çœkF d
´ÊL‡`õ4l¦¤(JiRJÖ,¡»©£bÓ°})***""\r" R"***(*g<ŠÒèh`P½)êu¾X=3J¯@jÓE¦1ãÏAIäŸz—ĞÑƒèjÓ3"sƒK´úT˜>†€„ÑÌ4îÈ¾¢—	êiÆ.z<¯cV¤PPsMeÁÈ©JÈJ¨±§b21I°zš‘¢9àRÛ<ŠÑH¤îFPZ6)õ©<¡èi|¯cV™[ì¦ƒÔÔW±£Êö5¢e'q”SÌ`uÍXîFSwcøP)©pAHPš¸Ü¤ÄTf—`õ4 `bŠÔiÜMƒÔÒ)Áæ—Êö5H´Ä(9")Ï Ô˜>†€§<ƒUrî7`õ4QRycŞ”GÛ‰\«¢-‚ƒÔÔ†.z<¯­5!Y)***""\r" R"***(U)***""\r" R"***(Ö‡ŒÀ4ğ…zKƒèj“ÔiØ‡Êö4y^Æ¦Áô4`ú«°æ±ŒJ‘QvÒ`úrıÚ,Âè6SG•ìiÁI§…8éEÚd0!>Ô ôüª@„ĞTŠ¥&äTrzSÊÂpjÓ+˜E<­:”)'iÛ©ª)Hj€N)***""\r" R"***(8 ¡S#4í§Òš¸s)***""\r" R"***(Ø1Š6SO“×ô¥ò½UØùÈü°zfOz•T0iB’zS6„eáF¡©„|w£Êö4ùƒœƒiô5*œšxN>ïéNòÔt¡=Jçzf¥Oè)
ŒpZhjv"Qƒ÷OÖ€äPçœ‘VŠSbàúÑƒêip})***""\r" R"***(!ues;äéúÓpOAKƒèjÔ™qb:©éH œçiÅªMÏa˜ÏJP=PÓ¶SJ€)Ü¥Q‰°Ó£Š\CJÈ"š¹qª F'?Î•—üéáKt ©ªcö¡âhxÉü*B2@5Hµ6Æ`¢Š—a=GçIä{ÖŠE)‘à”äg"! ä]‡ÔU¦˜sÛšP ˜¥U#©¥y¦56&Áêi@ÀÅâŒĞPZ¨4ì'“MÇ<T›?Ùı(
å!Vš4U,3ĞÓ‚ iû½.Áêi¦Êö¨üü'=@¤Ş3ŠfNzš7…=Åy¾Ìş€•+®3É§‚#|œb9ãö¤à‘‹¦É7Œ8¥§î‘Q†‚1NVSÚ²q2•+’«àriÊàŒÖ¡ÜEıiÀ‚8¨p#Ø’n´Í2•JƒÈüj}™‘2‘Œfœ‚¹¨—i9§‚u¤àc*#·î
PëéùS1şÖ”zC7H™{ÓºSdÓêL¥HPÀuQNW\Ôyoîş´ ½+7éy^Â—x¨Ô‚1šZJ2tPï5iË“÷Oäj ÀœR&=1C‰›¤JÎŠ $qEdâfé
¤§©qLŒSƒô¹Y.Ÿ‘ #E.})***""\r" R"***(GšQ×®(qD{$J­3R+¯·áP¨$qOU#‚sY¸™Ê‘.AéGJn?ØıiqşsSÊŒÁ†yQøSÑ—;±Q€O”nC’)8#7H”¿¥*±=GãQ«R( f¥Å#9Qì9v„~4üĞTcÆiàƒÒ¥¤c*a‘ê(Êç¨ “ÙZBF~e£”ÏÙzÓõ ıi©ÏCNÙ‘ÏZ—7Ià+Šp9Å `b•W=)***""\r" R"***(fdé·¡§åE ÷©)4bàƒ t«Œi(')***""\r" R"***(à‰(¤T9À?…;czT4O³Jƒ×ó¥ÈõĞ§ºş´'¯¹P¹<‡ÑH §4´¬fé¡U°)êsÈıiª Œ÷õ§/y¬äŒİH:tÅ*"‘pG §ƒÔéŠ¸#šxôü©£gqOîh±›¦ÀûÑÏsKƒœx
-s7)AÇ"’ŒdàT´¬féßê)U·v¤E*y§ªîïQddéØr 3ƒš\ÔÓ|¿z]§5-"\È=)***""\r" R"***(Š6Œf™ÇOÆ¥èˆp@ÛÒ–€2p)á9R€ÊpLŒæ—bç¥<&G“!Ób&yÅ<œö¦ù~ôî‡šM"\âœ9 =±N “RC€)***""\r" R"***(9Hc¢!Î)***""\r" R"***(9WiÎjW!ÂÃ•A<qNUÛŞ‘$v§ªîïPîO(*îïKåûÓ‘éAu$¸Ï4´QA>Í <óNUhUR¹Å=WÔqŠŒåLPœu©2ö GÇZ~Æô¨lÅÀN}hÏQùT”uëQî“ìÆ‚s€8x*.xà»NsRô³°ÜÔş”sŞ¤ €zŠ‹¢y¦1ÅJ›{SÎ*@˜¨¨v P‘J«¸g4å]£¬ÛFr¦
óÒ#ãƒúPªÉåS”qPìfà7Ë÷¥
1Ò¨só
pD=x©v'‘‚!ìiŞXìiR2:sO(;ÍÚær—ïúS‘@ıiêƒ??Ë÷©½ŒÜF*v‘K†ÇåO	ƒœÓ”n8Í.c7)***""\r" R"***(H¹õ•9®pje‰M8DCG1$~Pÿ Jz a‘Êånû´å«6úâ5FÑŒÓÂdg4ï/pÈ¢6©1hh@<ÓÕ çÚ/Şœ ô”‘#„cô§ªîÍ„iñÇY¶g(ÙïúQåûÔşJĞaP3K˜Ç”ƒË÷§ÂäŠxU PË¸b­6RƒL…‡pÂ‘W'©¼¿z<¿zÑnZV#òıéÄ)Ş_¿éNTp¸«R*$>_½_½JË¸ç4Åh¤ÙdA0sšz¦FsKåûÓ€ÀÅZb²c|¿zP€uæœ£qÆi|¿zÒ,P¡@ëÍ<qN ‚‚:Õ]—¸ß/ßô£Ê_ò)ê¥©|¿z¥tRDO…¦y~õ`¡ìiŒ¹ã5¬dPÄŒÍ;Ë¡ı)Uvœæ–´½ÀnÁŠk¦8üª`„õâ=i¦€) ş” ÅNÑàõÅ œf­JåXb¨Ç"”('EL#ÀÇJ<¿zÒáb1iV<öëR,y÷©,ûÕ¦ZW"1àu¨İ~X«-n”ß%kK¢¹JÊ€œ`~T­ÆXòV%jÔ†´*yxïG—ïVü•¤x€µ4Zh¯€:
rÇOÎ¤òıèòıëNfCp=*ÆíùS”mÍ9WpÎh»†yCÛò¦4c<ŸË÷£Ë÷ªNãJå/Ş”(ÇJ”ŒQT®;)***""\r" R"***(ò—üŠa@OTÁIè)|¿zÑ;)***""\r" R"***(+Áç4†¿¥XòıéyÎjÔŠD;0i<¿z—fÖÏéC)***""\r" R"***(Ã­›4L‹Ëÿ j€uj“Ë÷£Ë÷ı+HÈ¯B&©›=ÿ J´bÿ gõ¦ù~õ²jÃZ•ü¿zUŸZŸË÷ GÎ3V™vD)***""\r" R"***(ŒPÏ5hB;Ñä­R˜-qÖª­Iä­ :´îÊß•Pöü©ÔUo”?È¤eÚ3š})***""\r" R"***(6ˆéTn8Í<©~)ÍZe&†ù~ôyc¹§ìoJrÆÄŠ¤ìÁ²=ƒÔÑ°zšyˆ¦”"ÕWDsX‹Ë»WÒ¤¤à
x(æb5QŒûT)D'¯Zx¶iÜ.0(Œ€ôüªa	î)|•¥tÖ+r1F¥Y0ŒqL1ÔÕ))***""\r" R"***(H‰Tä8§àz
‘gßÖåûÖœÃæ!À*¨=éRù~ôy~ôÔ†¦7 tSÕJóKT™\Ìj¨#$ĞœÔŠƒ0¥Ø¾”s™ãµ(C(M¸¹† 08§ˆÔâ”D{ŒÔ ëÍ;´>b9¦˜¶MNPv4Î85JCR± ¥U^˜ëRmaÔR„ÈÎkX´ÇÌGåûĞÉ‘€IåûĞPœÕİ™‘*ÓùSğ=*®{Ò„æÍ#67ĞQè)Ş_½_½R¹|ãp=w© ÀÅBçcƒüTà€uæ–”GÀù¿JÑ0Sb*	R²±ş.{SÏLU§¡¤jX€*ç‘Í;`õ4òœpióL¿h4 ¸‚³ı¯Ò/Ş©>å*ˆn £h=ô§y~ôà è*Ó7Ğ‹Óô¤uôZ›fáÒ“ÉjÑ;Ú…Ôàã5'’Ô¢6¦äZª0)# RGµLM.Åô¦¤W´¹Q×­=IÎ:Sü¬ÿ ëOüÕ©œüíb½‡åHH˜3úRoÿ ¦†²ä?¨=ƒ}	U”´ğÈ*¸`Oæc­K††r X‡¢ş´#­AæsÀ 9ÏÌßJÍÓ3tAãş*p‘Hªªç59\¦¡Ó!Ğ,îR9¥¸58Çzpq¸©p2•pãšpÇZ€9ìiÀäf§ÉÑ&ÜÃ½=w_-×­=‡QúPàC¢ZB™ÎZqlÒæ{V2†¦2¢K¸{ô 05qÜRîRp1š—eaĞ“ŠS³°¨A4g×ô©ä±”©«À©—·Z	³Å??ç71t‹ ƒHX¦¢W'¶h2üÂ²qLÍÑw%Ş¾´õuÇZ„y ‘À4{2}‘avÍ<qÆ*°$ŒÔ±¾?ıu“ƒ!ÒDÁF3Ö¤M‡ÿ ¯Po_Zp8ç5&N™?ÒÔf¢ã~4¹>´¹L;a=¿:>AÎjUb=ı¨pFnš±:²“Ï4àÊ\8ïÅ=7R+77Hœ2÷§FÔ—Ö”;Òä2t‰¿vi@
0B±ı*EëIÅJ‰®rG>µ #Œş5u=éjL%H“ƒÒœ¡OAúÔ9?äS•ñÛò¥ddé2Â:ÓÉ_OÖ BOSN¨q2t®<2’iãnx¨G4àç¸¨q!Ñdê@94íëëPÆÀóÈ§o_Z‡=ºo_Z|}ê Àœ
r’8Í'8.Å1×šO¡¨Æ;ÒŒf£”ÉÓO\íÅFzÓ”ä~u.$:l•TáÇ¨ÆqÉ¢§•ÈLp)ù_îşµ\;ôõ> ŠN$ºhŸrôµüNY àÍ£'H”ô4¡9ëQ‡Jzø©jæ.›C•H94´›©¥$:B®ßâ§ ‡¥2”)***""\r" R"***(ÙÍKFn‚ƒ­9vö<S@ àŒûÒãK#ÙØ‘q·ƒR/APª“óNRàv¬Ş¤ºi’ıN)áA â¢W¯(eÀæ–¤{? ØÅ;³
JìhÔ‡I9JçÍ3iä<RÑ“¦<õçÚœŸxãò¡ğÔ¥A¨v3p¸åbH§‚JT3O  ~›±‰n>JZEÎijLÜB•F[’œŠr83Öœ‰¶•>è¥¨l‡Š6c‘OÏÌqM)èiÕ,ÍÅØ¾”l_JM‡ÔPƒšÍÜ…(P@§.Şæ’•p[7aÈ…]¤ãoëN†è(UÉÀ‘œõ©l‡)***""\r" R"***(X°jU
ÃŞ‡ÔRª•ô¬œˆq¸›zÓ€¥úÎœ*n' UdŠxBG¤'¤U!Gó¨rFn)ØjD\ŠUN2M8 :Vmì*ÅŠRœäS©Û¨¥{KW ÑÉı‹éHšuffÒ ª9¡sÀ4”ä9ÇjWFrHP S‚ç¡¤§ #9-™r¡TÛëRCÒ‘­; tÄJ¢İ)Â0N ¦…ÈÈëRF˜ æ¡³)DU@:Òí_JpLŒæ—aõI˜´‡"¨•* íøÔ@`b¤¬ÌÚSÒ‡ÔS¨ \¨nÃê(	êiÔ“Šwad1“iY©ÌdõÅW°ªŒ‡b%OJ~Åô§ydtÅ/–{šÕM‚C6/¥ÒŸåûÒ…QÚŸ3˜Á=1ùÓZ25•¤]ÂÄ;¨§ŠvÌœšx‹‚µRhCU}êV„rE9cÉÁ©<³ëT¤4ŠáiÕ+GÇ5&9­˜ÓA…#æ4Òƒµ(8§l>¢­6QÃê(sÉ§ùg<š<²:b­1ØTŒAr©^´¤ÔU¦ÊKB-§~êr©<”ñ# 
_,˜«M(?†€µ&Î:óM<V‘‘vB¢ƒÔT¡=j8ûÔÕªÜcZ<ğ)¦ jJGû¦®àE°úŠPƒŠZ*Ó¹I1¥x£aõê)”7aõlã¯4ê*ã&vQFÃê)ÔU§¨)***""\r" R"***(Ø}E'–G¥H‘šBê*Ó°úŠæJ‘š¤ËÏ"—aìiÀĞQZ-n4¦ZiàÔĞı*:kr‚_JO/ŞEh+±»¨£a§QWËƒ¸›)¦,œœTKt¥Ø{šÕ7cB!1Jçš ìhØ}EZwÙA–‡ÔT›¨£aõ¢h¤ÈöQ@Lu©6QNÀô¬Ñ‘‘‘ŠnÃê*R Œ`Rl>¢¯™hc$àš‘!éJ‘œæ¤TÇ5-ê&Æy#üšQ:bŸG>Ÿ­b½†„9äÓ„`ö¥Sª)ÊAè1Wvœ´a¨òGµ>Š9®MØÏ${P##Š}JAv7aîiá4”Sºf8'­:˜7€şTúcæ3Å&Åô¥œS¶QM)***""\r" R"***(Hg–†‹éOØ}E¨«LwC6/¥*Æ?„ÓÖ0OøÓ¼²:bØ¹µÍ.Åô§…#¨—ìŠ|Ãç )UsÉéNÂú~”£ØSNãæPãŠ]‡ÔR¯İ¥¦O;búR„LóO `qKéUÌ
¡Æx4SÊ‚1HƒÎ*‘JcHƒ@UŠyPG Rl>¢µNÅ©$6‚ê)Û¨¡Sš¤ÇÎ†l_Jr¢‘òšv¥. è*®R¨7aÏZ]‹éC6ÓŒRyÕJås1v/¥!OJp$Œ‘EZ¸))***""\r" R"***(Ø}E*.ÑŒÓ‚Ş”¡Ï­n5Q!v¨íJpx¦…qĞÓ«e¢©q6/¥œbœ ¦”Çèi6>q¦ ¼Ò©å[¿4ÚiÜµ!¾YîiUJõ¥¥
[¥Re)ÙŠ‹Ÿ¼)v/¥.uŠ²•F&Åô¥ )B’2)Bòh8*‚9¥Ø¾”åC·ƒNÂŒ~•Iê>qõâœ÷¥Çû"•TŸJÒ%*‡æßÒ“#8Í3û_­'©®F`º$ƒi?áNV^€şul¢œ÷©p%Ò%Êâ´ô¡ŞsNFlõıj\“¢L¥\dšvF3š„1Z]äùT¸#7GB`{Šr°<’3Q+ö¥k7dè²t8=x©Q†ÑÈª¡ÈèsR,‡hÀ•¤û‡­9Y@ã5`zšr³Ÿ©¨ä%ÓDá€<5.óQRî8Á©p2•$Jç‘J=)***""\r" R"***(D	ÏËÈ÷§Ï9¬š2•+“¦0?•=vgüj#OÖ”¹^ÿ fâc*Näè÷  ôª©1Ïj‘eÀäâ¡Âæn‰8aÜ~”„ç£Y	è:U~Çô©å±“¤‰‚88§ª¦2Z¢uÓ•‡CÅK‰•‰TÆE²x™NR=OãYµc'H‘=MH„tÍD¼võÇCøT8«Ê‹&.¤r)***""\r" R"***( Æìö÷¦íôcGÏ‚£•J‘.G­(É8$ÑÊˆöh} ‘Ò€01O 8íéPÓ!Ó°‚OZ‘9ïLÀşí*œg¨¨hÍÓ$¢š¤Ïó§ïJ×3”õ<ÓÕšbıÑNÈ  M.Tc*H2ÙÆqõ§©ÅH0F	Í(â“F¦JŠz}D­ÏËRdúÍ£S¸nö4SA8ƒMIÇ56d:D¨êF3NÈéšŒ *œdÔ¸¤‰tØşõ*5ğ)Êê+6Œİ+–$ÒüÕ>V4¹Ç8ÍG*!Ñ1Ûô§)1\t#àG^)8éX“ƒI…ôÀÇåJ£¾OãRC¦8=éàg¿JOÎ¤©²3öh_“Ş…î(ÙäS‚ sQdC¦ÅTì*E5É8õà)***""\r" R"***(ßdìŒ¥Ğõã¿Jp ÓIùiËœòCØç•1Ê@ê3NOİÅ0)=)ëœr1PÓ±›……§¨ç™ONœÔ8‹•P½)***""\r" R"***(8Ç­5FN)à`b£•™¸\nTu_ÒœFhÀ=Ešfn“¡æ¥,:j0€äÓ¶¶y¢Ä81B‚r:{Ó°AH Qzp
N9¨lÉÁP6€ß¥.Õì?J@¸èM(ô¬İŒÜc‘@9éR 9¨ÕH<Š’?J†ˆp1ßô¢œûÔ¢,ôÍd÷1p‘‘OO—­6 SÕ@Sr b”!#4”õû¢•Ñ”á@Œ{T¨¤g"¡È‡†Ãê)6õ!FÓÏ¬îgÊÄ)8Å8C†•~ğ©6±íRÛ@ĞÕ\sNN¿…9cö§Î8œ™‹@·Jr š…éO@r+6ìg$Æàz
0AR`z
g¢Š—"lÄP0*EhicÓ€ÀÅfÉh)B3ÅXö§Kfn 1MIHTÓô¥'-™8… p)û½(^x.HÍ¦"&MHª…\G4ä EfäfâĞwqüêEŒvıiUA=)ÁBô¬Üµ!Å‰åƒÓ4l=ÍIz]€”¹™”Å^Â¥D8ëHÉ¥T;x5FRC)***""\r" R"***(.Ãê)T0ik4îÌ„
1Ò¤3šhRML£›v%¤2Š—Êö†<rTRæ3v#'ôNG<Ò…àSÕqÉëNãI	°úŠO,úÓè¦>Q›ÔS‚Ú–Š´î£Y2r1FÃê)ÔSNÃ³ç“JÔåR~”¥8â´L,Æàz
P„ŒÑ±½)ã «Sh‡¡=OåN ¢œÖœ@=Eh¤†•ˆ˜db›åŸj˜¨# ¦” ñÒ´R)—ô¥Ø}E=Tç$qNeÈàV‘–…$È|¶Îr(ØŞ¢¤ ¢€	éV¥rÒhfÁëFÃê*B‡°¤ØŞ•²c°Õr¡<”å^9µiÜ¤†”ô4W°§ÑTŠVå‘ÓúP„ŒĞU€Î+hÈ¤a‘ŠZ+[¡ÙAç¥AíKE+´ÊW°ö4l>¢EZl«1»¨£aõêP¤ôIØC6QJ«ÈíéFÆôªM°Lı)|µ4ª4µwe$ÆùIéNäg4T‹Ğ}*ÑV#¯éL’2EKA õ«Œ€®Àã¦ì>¢§hùàf,ÿ tVŠA{ªPË‘€*aÏAG–º*Ó)+l>¢œ±ƒÓõ©?QŠDg5qw(o—†—aõê+UkìnÃê)<¼iô»àMî3`Çó£aõî‡V©”¤7aõí«è)BÍÒ´Lw¸ğ3M!Gj”ò)***""\r" R"***(5S?xUİ	è4œ
zÆ	ëNòÏ÷iUX6H¢è›±<¯aG•ì)ôQt!W°£Ë#¦)ôQp°úŠ6QN¢šbº°úŠ_,c9¥¢¯qs16Jp¸…Lõ©6:Q©B`z
_+ØQ±½)õI´$Æy^€Rì>¢E4ï¹\ÖWo,h'ŸŒœb—Ë?İªR±JCUH94´à´»©ªRd" s‘NÀôBô§' §{‹˜LA@=.Æô£czU«0»cFÃê)6¿ù4ñÓš æ`)Á=OåHºãõ¥AA*@SĞÑ°úŠujÈ®a¢>y  üiÀp)J‘ÔU\jlLAM`£¨ü©Ô„¨ëV™JcUI¥Ø}EŸ¹øÒ®ïâ«[)***""\r" R"***(HiŒ¸ GÏj}qcç‚1ëNXğ8"’€HèkXì>v;aõl>¢…z“ùÓÂ6:S8ÜîŠ]£8œ«¼)Ø•iè
c<¯aJƒ“Nü( ‚†ÑjbÁ¤ò–Ÿ´¼8£?-%'sHÈg””yj:Sö7¥Ò´MÜ|Â„©ü¨ò“Ò”(^”½jõ1¢5)|±´íéJçšjì|ìEŒ€E*¦4à¤@œ
²Ôî‚•Px£czSÀ…Z1ù—“´»˜÷¨w¯­Æx5ëºgöû¢ÉÆÜç94àGsP óNYzT8:$áAş*U]§9¨Uòy?¥=[Œ©¬ÜåE“"ƒÖœ¡q• sÜS„œ`œT8ºD›@§ ~µcØÓƒŒrj%I“\}ìSÔqŠ…_¥80=ñYò3)RdªH=E<T!˜w¥ó9éQÈbè¢À p[?…(8Ïäj/3ÔRï_Z—Mé©«fœ¤õTHAÎ)ë!<ƒ‘Y¸Ê‰eBúÒà{şu
Èp3JÈ¨pFN‘2 =ÏçR¢çïT¹¯oJ‘dÚ¡ÀÍÓ'TSÈ?¥m8ÍD$'iw6zÔ8Ê’¹2ƒğ§(©ü*b9Æ)êùê+9DÊT‰Ö1´`Ò„ù¨•:çÚ¤Yê?JÉÀÉÓDŠ¹jE
rMB¬"µ.n‘7z*=Û¹Íö5“Œ©w%Q“Í=UA¨U‰àƒõ§«Œc-ºD„ÍúR¦îı)èiËœğiXÍÒhx¹§„\sL§)***""\r" R"***(ÇJS9S°¹U¥E5‰ÇŞÍ4`”r£JäëÒ–¢SÆE<8Ç'š–‘œ©!Ôä'ÓÉûÙü)jyQ‹¤Léùß51iû×Ö¡ÄÉÑCÇ_¿OQ“ÍD=)P€qŠ—C¤L)Ê853dO¨q3tÉTJrªù¨·c§àIê1Y¸Ø‡I®äı)N:)¦«níJ:Ô4‰t‡*ñó
‘B`õÇµ8j“¦Ñ  
pLŒî¦)ê)Aî)Yºw$µ?búTJÍõ©Œb¥ÅºC¨ ôëHı}êt2tÇ) óOõâ£§§¨5›‰Œ©±È n´ğêi„“Á¥POAŠ‡I’ 9WpÎj*xlğF+7±ˆâ ı)W à7éM§&Şı{Té"D âMBsŒñN¨{™¸!v±íN1È¦îaŞ9ŒÜåPO)***""\r" R"***(O({ÓT/ğÓ·1ïY»é‚ êiÊ«œô¦SÔ·B?ÎÖ!Á1áç9¡@<
EÚsÍ;­K14*íÏ4õ_îŠ`9aRGJ†Ì]2E]İéÊ6ŒS=)é9Œ™›‚(n­Šp‹<n¡BãšPW 5‘<‚ˆİFëO1È¦† `rœ¼÷¤ö!ÁñÖ É¤^ƒé@ôN(“k”à‡¹¦)***""\r" R"***(H=+3>T0GJ#Àëj€riÜj[dJ «´ç4å hL‚)Á@è+6Ù‹¢€AJªg4”ô$õ¨d¸\†œ ¡z­?ôs'c‘J#dÖ—ĞÓ—îÒnÄòÜfÇíR*d}ÑïNUÏ$SÖ?N+7"\R±ƒÒmñÈà›z-Hy›•Ìd‘V¥8(-9§y|õ§#€)***""\r" R"***(Cw1i)***""\r" R"***(T%°E<D4ª§ïS°OAPÙ)***""\r" R"***(!ÑÅíÚœ!=Å,_ÒŸYİ™5pX”ƒ@‹œí§GŞJærB,YÆiDl8”ùR‚äÿ õª[1jìF9»Ò”g¹§…R:T^Æn6±ş2FI¦t©“'¡¡Êæn,B¬;RÁ©ÈÁ¤Ø¾”¹‰ä#
 ä
z®y4»Ò€ TÅÊÅÀô`z
(¦‡`¢ÓŒ|iaÒ·?xæ©;2’#Ø¾”Pr=—H“ŒU¦Ô“Ndg¥ôû¢b­ Ï+ıŸÖ”B=1O¢©I‹•¨Î Ç­+ %.¡­T´"ÃF"¡Ï#õ©9â‚¤¸¶RŠ±})8ùE;8£#ßò­ã°¬ÈÌdõZQ?4d‘ZD¥”E&Æô§GZ+R†loJpAE.	è)p})***""\r" R"***(Rlí_J6/¥;ašJÕlRI€Rz
pBzñH	)ç¡­"Á¢6@4›ÒƒèhÁô5©7bÁäÖBÒ¨;ºSê”‡vGågøZ_%iô OJ¤;Èg’´¦2;Óö7¥z»¡¦Èˆ#­(ò)å2rV€¤tSVš);sÍ8E‘œfƒèiË÷iİÆy_ìş´»v§ÑT˜ÄØ¾”¦,»J¼SÈÈÅh…ur‡<Q±½*B¤9£ĞÕ–¬Æ=Í&Æô©0})***""\r" R"***(>†­fFc'ªÒ³ÕjBê(­ÁqY#šO+ıŸÖ¤ ”»Ò«™”È¼¯öZULq)äc­I±Œhò=}©<¯öZ™TÉ»Ò¶R‡¿ ˆ Â¤X€­< :
®dDí@B¦*QHÊä
¥!shE±½(ØÔú ÏJjDó1›ÒéRloJPƒ©§tÌbf§p9æ (ô¦'"?+ıŸÖ+ıŸÖ¥Áô4`ú¤Ò'˜‹Êÿ gõ¥§z“kÔ`ú¤ÅÌ3ËÇzp¥
IçŠpŒcîÕ)@„õ§y_ìş´¡IëÅIƒèj®Kd^Wû?­Wû?­KƒèhÁô4™‘¬\ğ)|¼w§`¢ŠÌÄX¹õ¥ò¿ÙıiT€y§‚CV¶3#ò½¿ZQ>ŠcæC67¥y§Ó†ÌsM1İX²3ŒûÒˆÈè¿­H1:QV…ÌÆ„'¯»Ò–Ÿ±}+DK™Åô ¢‘Å8©•VCæ±â”)?xşêƒZE)***""\r" R"***(Hcm
Cn«Ne p(@AäU¢”´Oï
]‹éO@QNëVö"Ø¾”…x5!AÚ“czU+)***""\r" R"***(Tc|õ§ˆF9 )'SÀÀÅZv)MòñŞœªOŠURi¦Ù\Ã„Y=h0‘Í8 zœSÈÈÁ¦ÊNäÒ•UÉ.Åô£búSÆ($â—c
pP@¥ªˆsØfÆô§$dõå]İéB‘ÑªÓH~ĞLFhòıéØ#¨¢©6ÇÎÄXò3ŒÓ¼‘Şœ?Z¤ÌhŒ€JDô4ìJ\CVìAî)ŞWûTáĞQT´)T?.óëI‘ĞùÔm&O?¥Æ{×Òrè¤J	)***""\r" R"***((sŞ¢ÜOFıhƒÃ~µn‘:É:S„„÷ÏÒ W¤Aß5“‰Œ©«À9©=üj°Îx©à`šÍÁ³RÔ~ßö…9sĞˆ¶¥"§Ù£7M(9â3Ş E<9=ÿ 
—ÊœGîçïÎœª*Ulpj]$ON'%³éQ	qOĞÔ8J‘%*‘¸qQ†lõ§©ÁÉ›“¤É—>¢ïQ¡Ï#õ§r@ëß5›¦c*]É³Æ*D#¦Z„gÿ ÔiêÁª\,dé“ ldx÷-¿•0O›‚1•"e#qÍ=9<Uq'§5,n VR‰“¦MÜ~TàHê
„y'ğ§†éÏëYr3'Mqù.{şu
¿cOéY¸ØÉÓ%+ÎqN
äñQäçó§,„T8ØÍÀ”.M(úô¦y¾â—ÌÈâ³pD:i'4å8ë‘Å1[<b¤qÉüêlféØpf)üö¨€iÁˆ¬Ú2p¸ğ23‘NUy'zp8©³0t™"¯GâiáF=j0r8§n$`Ô´féÀô¢š£#ïÎRC¤˜äèx§Œ“Œ~”Ğ»zÒ)***""\r" R"***(Mµ2•ûr	§ ;ºÔa›<xÏz–ŒKäçuIF
>iŞcz
‡gì‰Bç©…(P*5byéR)¡?dÕ„éGJp`FzSBç¡£aõ¹Q›¤î<b Á8¨†TóR!8Ç)***""\r" R"***(XÊT‰U@ Rí'¡4‰÷E.HèjyLıŠÔÓÂ°04Àş´õã¾>”œY˜ã“À?£hÎE#dr@¦‚szÔXÂT‰Tdâ*ş´àüğjL"P	8ª¥MF‡	§dôÍK†N‘*€zšpPê0¸ã­Hª"±’1p° Ò•FN))ÈZÉ¢$EP PF)***""\r" R"***(FŠ>õJŸv²hÊPB=ˆÇÒœã¥ éHÁÀE\p*B Œ`PŠAÅ<Æ;VrdJaH9§€	Á F{ÓŠzÖMØÍÃPÚ½@ ("€ t&œ ƒPÙ. ¹'Œ~5"¨=iª˜ù…>>õ)***""\r" R"***(ÜÊTĞà3Ü
\•à`ÒŒÒ…'‘Y´c*i‘ÈÅ93»¥5AÔŠF8üªZV3tÇ¨FE( r(P@Á§ª^k6C€¨Ê¤
¥4)ùÓÁ¡¨2•4.ßF ôïN*3‘J'³½Œ\T‘öÏëMT ç4åÃf¡»™Ê#À är¯<Šh\t5(éYËC')***""\r" R"***(DòÁè)ÛH8¥BriÃäÊRv%¡?ò*DÈŠD Oz‘S#&³ÔÊQ¸Š¹=8§¬c?ãB¯aOQŠ—s7Ù§8Çó¤© úTâ(RÔ¢6$QÓË’1Rô0’@<€)V6ÎqšE'#õ"œf³lT<Œà
J}“3œP‹’*EŒ“Í*‚ÃŠrw©lÁÅ Œ¿¥Y?vONŸC3”uˆÀ`ŠzÇßìfœŸtVnFN#yşP‡¦?:“¡qéSÌC£D\t5"¡
)â0zrÇéúÔ¶fÕÄò½W±©r=hÈõ\Äy^Æ+ØÔ¹¢€sÒšZä^W±£Êö5-\Ì\¨Œ!^€Ó•sÂGZ¥&Ø%a6/¥X=3O	ëNÆ;U&ÊI²!=ãN(@ÿ 
x8¥Ø}Eh¼ÇÊÈğ})***""\r" R"***((@FjM‡ÔR…©XVc/oÎ—i¤
OJq@j“‰ŒcŠk!<b¦d dSkX»DB,ö4y^Æ¦Q“ŠVPEl˜5b+ØÑå{–ŠÒ2ÙÂÀäRy^Æ¥¢µæB 4¡I8Å>”)'ªMÜ-r2„
C‡…JT“IV¤B/+ØÓ‚ÿ ×§€IÀ§l¬dÇvDTŠJ˜Æ1M0æ·Rˆè©>ÎGZU‹ŸÎšhi"<CJ€ƒÈíRô4Ş•¢±i\(Á=8'©¥
¥1)***""\r" R"***(Áô4`ú}Ó°
IÆ)|¦<âOOº*À‹ÊJQjZ*“Øß-!R*TàMn‡éZEjˆè¢•>ğ­(6œg`ú}iØÊê)***""\r" R"***('•ìjZ*Óv›Z0})***""\r" R"***(>ŠiØz22™9*i~Æ¥ ’(ªOP¸Å‰ñÅ=bõıié÷E9 '‘WÌÁ±¢.:U‹Ûó©)B“Ò´R'™4\ôü©\t?JT©æŠ|È9‘·$ô¤òJœóV)§ãT™7d8>†ŒCO£«¸®5W=sNUÇLÑN½>`iô¥;Ó‡'ƒŠwlM‰°Qåıiié÷ER3nÃc 4¸>†ŸE4ìl@ v§"’”¹#i…Ğ”QEZi‚iˆ@#‘“ŒÓ¨«HMØf¡§"‘šxQŒ±¥GCT'!zŸÊ®>ŠjÂR°Ğ¦•cæ©¸dƒNoI!9ÜaBøPÔú+D¹†ì´ğ¤Ó•F3ŠpRzSˆÊ‘Úšcï‚*b84˜Ï©1)‘l¦§¡©Z1š jÖåsí#ŒQƒèjm‚ƒÔÕ]˜PŒÿ JxLiè ÓÂè5 R!)èhòØô©¼z6JW+œT¨Æ?JpqÊŒÔ4¾X=3VŠL‡ÉõÅ23Sy^ÆƒsT™\Ã/oÎ°úŠxRzS¶SL9ìE°úŠ<§ô©B sKM0öŒ„DÙäRù^Æ¥¢ª÷hÆ*àÔ»ÖERÜ= 0W±§€@ÈıhŞ{ŠÑ\¯h"Æ@ãõ¥òÚ”FE(œ
´ÊU )Q‚(§ìÈäš0O­hĞnÃê)Â0zf# c4å¸?™ \çå]Ã'=qFIàŸÂ¾ÅÀÿ H]ààæ	=¿Zˆpqœ{SÃ‘ÅfàŒåE)ÁÍ<×5 r)Ë&¥C„¨³Ú¤Ç"«¬¸=qR‡àk9@ÂTI)Ê[ëQ	28§,¤¨äf‰(àõ§*©¨ÄœtÍ`ïQÈdè’lç â”p*0çÖ¤Ø5&N•É7iş[Ãğ¦#O2Æk9AèŠ»‡PGáO “Qù­œ)***""\r" R"***(89Ï'ô¬ÜL¥E Àp
pÍEæÎiÊç®r)***""\r" R"***(C‹Fr¢‰U› æ¤½Bzz1ÈúVmJ‘:†QÀ§TK.;âœ$'k7	QcÇÖ½:ÔJÌzÆÿ z³p1tI#½9K¢£ÔåoSY¸™º,#ğ©Qj®ğsR$œVNÅÑ,?ZNEF%À?¥.öõ¨å3t™ -´õğj$~ıéêû+79R%
GzU<
vÎô±ËÏZÉÀÉÒd	ëÅ=PãƒŸ­1eüièäô¬Ü,Œ!ÁHê¿­8Â£$M(b:ÍÅ“ìI—§Zr©<Š‰ã9â§#5¦r¤J8šrJˆ1îÕ"Èq“Ï½K‘2ÅÙ¥(ã¥1dÏz“{zÔ8³QbùåiŞ_½ vÍ80<T´dè‚¡Ïğ§ªüÂ“=OJ@HéSfg*Dª¹ïÒŸP«18ÆjHÉìj\Lİ6J«ô´{Š+>]Lœª»†sJ Òg¹=I ş4œLåLr–Ç”î´)$dÒÔY8
ƒ=ê`ƒ¿5†ªHşµ-X‡LyF©c9ÛNf=
ş´ŠHè{ô¨hÉÑ¸¢>}}©Â<… g¸§)è7~¨fNzr¡Ï–œ ¾œVlÊT…D=ªUNÑQŠ“>¢²’9åH)B“È' ¥}qY;ìe*B 8Æ*EP9#š`$w§«gƒY´Ì¥LzMH#9¨ĞóÖ¥RHäVrF“¹")äOòıéŠÛ½©I'šÆQ%Ó£zP“ŒSCs‚0iÁˆã5›L‡HQ|Ó•<R¬™ â—;øéY3'Uvœæœ«»½4)êEmİªL¥L`FsND\R§zz®áœÔ=ÌÜT8â‰£šm©îÔ39E Í<&Fs@LŒæœ+&îbà vœ†x¤UÏz•;Ô6g(h0r)***""\r" R"***(8rqN	ƒœÓ±+7.Æ.BóNTğ)Ta°iõ›fr€Š¸9Í9FãŒÒ§_Âœ' T6e( To¯Ög="w©#ïY½Œ¥awæ¨ØùM*®áœÓ•qÀ¬Û±“€±©#Tà
E‘~íK‘›€‹#ŠrÃê)U°iêÄõ›“1qNÓÌ,)ÊØëO©m˜Ê,‡Ëõ&œ±ëR“Šw—ïPîÌÜF™õ§,}ñŠpR;ñJ=*Ñ‹WiÎiá	ëÅ8g)Ñ÷¬Û¹ƒˆÔŞœ#ç­:?Í²F„# ¥“NÁÆ{T‘v¨lÊQg¦)â 9§Ô‹Ğ}+&ÌÚ#U$`”ñ4µ%#)EÀ8ÅKTş_½cBš"ÌƒÉjQî*B84dãJZˆ„ÇÏZ<¿zšŠÓ˜vdh„t§¬g"–œ„œäÕ	¡ ÒŠ’ŠjB²CUäÓ‚àp8¢Š¥1…(ô©×ğ©dg5j@1cÏ½<J–Š¤À„ =(òıêj+XÈ‹²‡±¤ØŞ•=²•‚äz_/Ş¤“µÈëÍZZä~YëŸÒ/Ş¦¢µRb e`}© $àT¯÷%j›±ka…Hê)*J '¥h˜Y)***""\r" R"***(òıéØ'¥;Ë÷§V‘ĞI"0àÑSÀÎiµ¢eÑ°°éRR“Š¤ÂÄ>zÑåûÔì»FsIZ)XiØ#<àÒìoJ}ù®'¨ÍéFÆô©¶Œbœ§pÎ*ù…dDã“G—ïSQT˜È|¿zp©(­^ÃP`\T±÷§Vˆµ±XÂÔ_½Yºi•hd!0sšu=†áŒÒy~õI’İ˜Ú)ŞYëŸÒ•Woz´Ğs)***""\r" R"***(O^)|¿z’>ôêwaÌÈŠÔ‚,œf¦¢šm‹™‘ˆHêE9c­:ŠÑ^ávÃ¥<(y¥^ƒéEUìJwP‘Å0F§R…-Ò©6ˆÂIÈ"ÀŞµ`&sCôüj“dÜ¯äµ(‹îÔ”UsÙ’Ô¦jtg"–­IØ.Êë(Å8!îjjcıãO˜–Æy~ôy~ôêzıÚ¤År//Şœ%iÜ‘ö £Õ=)***""\r" R"***(Ğı*“¹¦ù~õ5´vv"Tô4íéO§'_Â˜¹™BO4¾_½MEZØ‡$3ËÚ8Å%<‚{Òy~õi‹˜Tû¢–‘FÑŒÒ“M.¤9!Á23š<¿zUZbæ y¥ ” ĞSêÒß/ŞƒGZuÉçdF)DLjJ)¦R“±½({ÓéC‘U©\ìhAŞœ±cÚ—ÌöıiÈãœsL|ãDyã4¾KTŠwâ–­!s²1Æ¥XøëŠx$ŠpsÜU¦ÊU—ïJ"'¡§ùÔàr3T?hGå³GÔT”+B•K‘ÑOØAHô |è@„óKåûÓ€Å*ÇªIêj7`õ4†1ØÔ_½_½PÔÆ,Yíš_+ıŸÖ¤ ”U¦ÃÚ"1<Ö”D ç4ğ	8õiØ~ÓAŠ„K±½*@¤ŒFÆô­"ÃÚˆÆ1J‰Æ)ÊšQÖ«˜=ª?&ÉçŠ]íõ¦îö4›ı¾ñÄÿ O"@Ù?{¯jz}ê…g4ğÙ8Åfàc*lš•FO¢”ôfÇ¡ÂÆ.›d£#©§+1íšˆ;w¡Çz—™Ê‰0$õªØÅD=)éÈëQÊe*(•\‘œÒ€øâ£V+Çjplğ+9FÆr¡Ø8š‘dnÀşuyà¤rfâe*$èÄÓËyôéP«2õÅ/˜IÈü«7™J‘(“”á)'¿J‡ÌÏğÓ‘9©tÑ‹¥äN¤üiA#¡¨ÃÆ—yÇŞ” béBG­9	=jb;gŠ•X.x¬\Œ¨“( sOAß
ÉœÓÄƒÔŠÉÅ™:)***""\r" R"***(“ OJz†íÖ IïR$£Nk7PdË¿7ZPHäT^nŠ¼Ô8\ÅÑ‘ #T©˜¨îŒT£æ³q±“¤HÉ§*°šon(úb¡ÄÆT	Up)Ã‘ÈÅD­“‚iÀàæ³”LİäƒÅ9O</ëQù‡Ò!'€k‰öœ”õfÕlzÿ :”zŒVmJˆííëBœ¶I¤£µ.72tìLü5 b?Z…àzœŒÖR‰Œ©;ŠzdŒƒŠb¯sOzƒY¸™¸§qŸ¥JúT+•şªZ2tÉ)Up*5'¦iõ6d:cÆO$bœ£qÆi‰»×Šx8êü*¹“¦‡õ4øéèiêëƒøT4C¤J¼vÇãKLR@éšrí<Œ~U›‰‹¦9AûÀSÔÔb‘GGáNõÉÒ
	üè¦†îsõ§G?Ò§”ÅÒ±"ôJUlqŠj’G"œ	‚*Zd:céÊ`9íŠzî=ø¬Ş†R¦8N=GÊ)A<O²z£9Sºœ‡œS@4ª§<ñøVm\ÉÓ$ EHED¬ËÔÓÕ²:TIJÇícÉ4àsLV9Å?‘Ò±’ÔÅÓv&FsNQ´b‘_Œ0§ÆF*¹Œ©
§i©ñœâ£'´ñÓ­CHÅÀ•CcÆ”§uü©ƒ+Õ;23ïXÈÍÓb’OÊF3OŒ`QÙä~b¤†éYI¸2dç4êbN0iØ‚±hÉÓ£qÆjP„õ¦"ç¥N˜ç5›!Á BzñG—ïOU'9â—aõÁÃQ ÷¹§®1Å
¸ RÔÈÍÀpLŒæœ)ª§SÍ8•“1påûÔ¨pj5T£y9³w3äúRÑš'›¿R%MMß…HŠsœSQORF ÆLÁÀU3NT+Í. è)ÉéPÙŒ¢ƒË´ğ¤ô©Ş¥TŒÊ³lÅÄWh©#Œb—ĞSdæ³z˜J,UzGß…é·ñ§ªdb³ÖæN- À`
rÇÔèÀèEIå‘Ó<ÆrˆÕ‹>ôà¬Jx°¥ÃÓô©r2hCE8!Ï8§ˆò3Y¶fâ1c,3ı)Á6óİiê¸Å9W')***""\r" R"***(PİÌ¤˜Äv§ìoJUBJ‘÷‡éRÙƒˆ‰i|¿z éšBŒ;VnZ™I4Ää^šU­€Vm™8ÜpV=©ê	ÇjEäiè¤r}+6ÌåÀp8FIæ”Ô
‘Pj\¬gÊÆGZ*B½ˆ¦”ô57LQ¤db›åûÓü³íJ#ÁÉ®,\¤~_½_½K…ô¸‚­7qù~ôª¥y©„C¸¥ò×­S´!¥UÜ3šyLéF è*‰²M8/`)B3NQEÂÉ#ã“N})à:
¤Äâ4)=!u©0AJc8ÉÅZV"¢¤Àô`z
Ñ;d0)# R{T”`zVŠW"<sš*LAF ­#&Æ0FqIRQè+tCÜˆ¦NsHMMè(Àô«‹Æ,|zRù~ôáÈ¢µL°¡Iè)À)pAZEu¢¤ ƒMØ}EhinÍ?aõ«êE4ìB//Ş‚§ëSm”`z
|Ä6ÈB×Š
Õ)°»1Ô~•jL¥v@A§( sOdÉÈ•W+U"•¯¨23š<¿zu(BFjÔ‡dÆªí9Í-;aõ\Œâ©H,„
OAJS­8)ì¿¥)Bx­SÌˆ€x4ÒœğjlAF ªæ²N§,L§5 Lôï/Şš9=é|¿zÆ{Mê*Ô“0Ï/Ş/Ş¥1qĞÒl>¢´æ%²?/Ş€ƒ¹©6QJÈÔ…v3ãT»ñG•ì*®Éº#9¥X³Û5"®:â”AV›CLo—ïACØÓÊ3Å%h˜®3czR21Ô«÷©\t«Nâr+ù~ôª»NsRàz
0=U‘<Ã“ĞR„=Î)á	íŠpÃúS½‰æ"òıèòıêj0=4Ğsù~ôy~õ6 £ĞV©‚d>_½8T˜‚ u_Ò©k¸]20¤y©0AA õBm‘œö4Ò™9&¦ ¢ŒAZ)36Ùˆ†œ±2œÔsĞS¶QNì—"5R"NØ}E*¨j“¹/V2Š”GŸáy^ÂµDİP=Kå{
<²:bØ]	ëNÈ»Aè¿¥R±›dt¡Iè*O+ØQå‘Ó¢0”T˜‚“éúU]‹™Œ¢Ÿ…ôı(+Ç Q¸Ô†QNØ}¨Ø}E	 æJ#9Éâ—czÒ®ïâ5cæ°(Ú1šZPÀš]Ãû•h9ØOu§ª68)'·áORHæªì\÷±½)|¿zx`6Šp ŒàU'pRhˆGÏZyV©Üß¥.)Şãö–ÜŠ('¢,ô…¸ı¤HÀÉÅ/—ïRy%zÊ‚ƒ±­U‡Îˆü¿z<¿z~Ãê)Áaš½¹Æ,J{Rù+R¢pŸ;aşà ŸhB"¡ GÎ3øT»Ù AV˜{B=¥GJ*P…†x£ÊöZªDŒz
rÅÙ§ydtÅ(OZ±:ˆü‘Éõ4 úşu›œf”;
ıÓ?ÕùPd«‚pøÓ— ñÍD²±8ş´ñ!:ÍÀÉĞ%»âœ­·­D%>£ñ§£ŸAQÈdèù)'¸?Jr®zÓAŞ¤ß‘RãcPF:ş•"ãŒ8#Ó•ˆ”¢fè±ôå˜4ğÜ{Ön&nˆõfÿ :xcÔŒFI¥)***""\r" R"***(ÕŸ!Œ¨²U%‡4âqŠ9ëÅH&ç­g(Jˆ¡Nzz¯lştÑ&zş”àØ9¬Úfn“)***""\r" R"***(8ÇéLzŠr¸Ï›‹3•Tã=©ø' ?…1\ãŠ|rzŠÍÄÅĞ$U8éù
P¬yÇçH²)wÂ³”nbéj=AÇOÊœªAÍ1d8ëŠw˜Ş•‹‹!Òd‹×¨üiË‘ÓÒ¢Á§†#¡¬Ü]Ì%E#;T‘’MA‘ÔTñ:ÎQ0•\ŸJ)¥ùãõ£y=qYØÉĞõ$ŒŸÒ£;S‘ÀàÖrFnú‘#€:S€9§£ Vm3S¶ÃÕJÔˆ­¹¨Ãx©Uúâ²qÔÊTÛ‡ıéÃ¯OÊ“9ëùS— coåKÂT‡*gÿ ­R,dñ¨ÑöñéR	}Åg(Ê“2*E9* üò)êä{Š‡Œ$J÷j!Ï5Ê¤Àõ¬ÜL;Ú=)Tò)¨ıÈïOŞ=)***""\r" R"***(CFNN8&8¦«¢	=jLİ!BóÀ§¢‘šD‘Ú¤½CHÍÓĞQ´‹úR«cƒNw"±qÔÍÒ	ÔõÉ÷¤ ¢œª@ùE'g*v?•/ÒœsJš†‘“¦˜å9)è¤ç+úS@ÀÅJ;â¡™ºB”ô§9Æ?J3JµŒŒİ1Ê¤zRÒCKÓŸ×5›LÅÒç1NROR)›‰îiêÇjÍØÍÓC‚–àTaŠbw©ñÖ³hç•;	‚§šx ŒŠO½È4p=«)DÍÓ¸«ÉÀ§…Çø
j©'=©êÍĞ~µ“V1•!È¸æ¤P1Óó¦ÇUüê@F:ŠÍİ™JŠ©¹§í'ŒP¬3ÇãRsÚ²wf.†„9§ç…Çá@<ãJŠx'šÊF2¥a:d~5 ‹¿ó¥\ƒR ÅbÌ\Hùàö©UqŠE^Ê*U+ü_…fÌ%Lÿ ×¥Ø}E:ŠÎZ:m«ØŠ]‡ºş”å+G4àG^µ›¹‹€ÕŒĞÓÄd 3J»{jENrk2X‰ iéiT2ô}êD O^Õ)***""\r" R"***(³@i‹ØÒìçîş•%(#¸¬›lÆQcU?J‘8ãšàTˆÅc-Ì\Aæœª	ÀÅ* O5"(Î1PÚ0”AS=J«‘È¦ª‘÷EJÆáY³'¡@§*dqIOŒg ¬ŞÆ2¦,cTª„ŒŠ#C‘ÅH‘šÍ³>Aâ¥p9¡x#µ<qY·c)A\ç•¤ÚEı(E#îö§œº+&a(XfÏöJ_,öÅ>•@=qS©Œ¢Ä=i|¾r1O• 'š‡sDj©&¤UÇZ6¯¥9 läT¶fâ
 ç4å@"WƒK±}+&Ì¥›8ÈZdıßÒ ëR"†Š†ìdà1`Èâ‘ùw©§4õR"¡ÈÎQ#ãò©£CÏ4à£ â¤TÀä}+&Ì\Hš1Ú¨ôı*}‹éMh²x¦ŒÚ"Eı)L9ô©0(STU©f@a phXØGéV6/¥Ò­HD!XöüèØ}EM±}(ÚÆ8ô«R™–}¨ò½…Mµ}(Ø¾•\Ä¸ùgÚ—aõ.Õ¨Ú¾”Ó%«l>¢œÆ?búR€AVÄ4FO_ÒœG¨©  ¤eµhÄÕÈÊƒÚ¡ÏTH¤ªOQr¡»¨¤Ø}E>ŠÑ0å°úŠ<¶=)ê<ÓÀ ­bì¬ˆ!_¼(Âú
”€zÓY~Q[©"u#(Iãl>¢Ÿ±½)Ê£jÔµ¨‡Ë>Ô¢2zş•.Åô (j¤PÑÇZpŒvÍHp8¥
AV¤Ø•ªş”`z
‘£îGëIµ{­>f+ŒÀô' §í_J0 £™ŠéòóéG•ì)ôª<Õ)ÈÊö¢2zş•0Œ‚œ‰‚>•jCZíKöqíSì_J6/¥Z˜6AöqíM0°8gbúS\V‘˜“¹ˆ÷œ#8ëR†\r¿¥.Õ<â´Rr-‡ÔPcôıjPª@ ¨9âµŒ¬.b+ØQå{
“czQ±½*ùƒ™òø÷£aõ CG»Òšbnä[¨¥UÇ\T›Ò”FE«R%»ØŞ¢ 
—czR2âjDÜĞQ´wô§ì_JQpµi‡3@Ç"—ĞS‚r9¥Ø¾•¢bè(
{-<*@©¨9´Nà@T÷`z
œÇœü¦˜a=Ö­Xğ=(
[µKäjUŒÍUÅtEå{
<®sSl_J6/¥>fMÆ,`ôıiJ‘Ú©ıÑJàgíT™‹ĞR¥I±})¬ 8i²nFTƒÒŒCR')Á9Õ¦W1¡§ ªM‹éFÕôª¸¹†)***""\r" R"***(Ğ

d`/éR¬~¼S¶/¥\AÍ¼§ô¥XqS²Œp9¤ØŞ•i³7!«;Rìÿ gô§®áÁRÕ+ÙÑéJ#Ïğş”íª{S‘Aê+E±-ØA?‡ô£gû?¥Hèÿ UÙ›™ÏöJ6³úT€bŠ¤î.rÈ8§ `-IO
¤t«L\Ì‡a¥Ø}EK±})pAZD—")ı)DG¸5-Dó2gJ#`y-3D{?Ùı(Úzmı*J $àS»'Úìÿ gô¥ä/éRjz®FZ¸{TB!9åJ_$tşU>Ãê)67¥4ì/hDô§¨äTŠ¼r(Ú¾•¢w;è)B˜4àƒ<
xV8§{´"ç¡©<‘ıÓùS¨9#ô©²(L^Ğ„B3÷Jp‹ ©Ö—÷uVhˆü¶ëIå{
””Æ1FäşïéV›°B/+ØS•íšm=ô¥ ‚ªìJ¨À‡Ó»¨©6*ŠBÃ²Ši‰Ô#0’y4±éR¸äS‚©ÅZv´"X¸éùS‚vÛúTƒ `-.G ªæ¸{TGå{
Q=Gä)ùOîÓÂĞSj~=Ó•˜öÏ½3zúÓ‘Æ+õWı…•+lHõ©÷?D®3‘OY9ô¬œ.a*7$Ş¾´å`9¢óKqJ§iÎ+>CEØY‡lS•ÿ ½P¤ƒéõ©QÆ8æ¡ÀÍÒ8ÓÑñÁ\TLàœ
tyƒŞ¡Ó2tÉÓ“‘OÎj$“E<È ¬¥LÆT¯Ğ>1J=)***""\r" R"***(D­:TŠÍéšÉÀÍÑ$RÇ½:˜¬àã9#Ö³q2•!èØÇãOO Ô@ó‘úSÔäf³p1t‡©cŒ=iÆš­Í8ŒÔ:m˜ÊŸrDb;T‰'+P¨ö"¤GÉæ¥ÀÎTI•°84åbO-úTaò9§ t#ğ¬eJŠ¹%97~ÈsR¤œò+)DÊTšÚ8Ïµ8tc”o_Zp|qšÉÁ˜ºC“8æ¦B3œâ¡<†©Uˆè1Y¸J‰!$òhx¦yƒ¾iêøVR„© ç%z¦pIÍ5$†EH®3Á¬œLeIŠ¨3òÖ»‡SC‘Ö”8ïY¸³RdˆGaOS×ÿ ¯Q#Æœ$#ŒÖnR¦Éùù†jMãïéPÏQŠ‘:qRâbé&HFiê¼ò;Sˆè?‘[p¨”L&(–¤QÀÄàş*µ“‰„¨Š‚74'BiÃ­fô1•1ÈGCN¤RHäÒsY5s'D|hZ;ş”ØÏ8ãâqPÓf~Èz:7éRŒÕpiéŞ¡¢"@ä{zÒŒ£)Ïp~”¸÷¬š2t…éÔzSÇ¦)¹ÆÜşøğOJÍ£7I1UO]¹ñÀÆ(¢³jæ.’C•›Ó4ñ„S3OU9Î?:—fà;æu÷£æ}éG«ŒŠÍ£)S# cñ©Í'°§¯Y¸èdé‚FAàÓ¶·¥
Ê~”ş£­s½Ì¥HEş~5"®Şô‰qO\õ¹Œ©ŠŠÉ¥Ø=(=F)@ÏcPÕÌ !Çœ#ã­*ôéN
OAY¸™ºwªGñ}*U#ŠhAjHÆdÑ˜îôÿ ˜qÖ…_îóNÚGjÍ£A
¤c)***""\r" R"***(O² *09åMH¿z²’0•2TÜOµ=wgŠjtæ£ÿ ZÅÄæ!À‘È©=Å1W'œÓÀ?ZÍ£	@•TNhÆ:œP¬GÅ˜™¬¥:` @Í=W8)``R Î¬Ù›¦„TôëSF3Á©1ØS×î¥g#PÔ^”ı«×«Ğ}*EˆÇëX;™8XfÒ)***""\r" R"***(.Ã9.ÁêiU@â³nÆN#=¸©Q1‚)***""\r" R"***((PsN\çŠÆ[˜Ê˜rr4åE(\÷§ 9éÚ³{˜Ê˜ '¡©¼(@&¥L÷/cSHb§÷E>8ÏR?rã<jTë)^ÆR‚°ÔC€)àm S•Tñ})õ‹hÅÃQdÔä õ'µ=#8àâ³lÊP€ƒƒN(E*®s¸S‡5›g<à1F[šxA9Áğ óI´ŒeH9"— Í(ù¸¨§©=éY96a( aÓµ=SûÂ•WŒÚ€ŒäVm™8p4nõ"®s‘OXÆz†Ìdˆ–.:f¤HÈtT›©©"@EdäÌ¤¬1c gğ£Š“`õ4l¦¡İ£«€UÀâ€Ôˆ™æ¤ ê+7±›BÉäŠk Ç¦*qÈ4›©¡H‚éFÆô©¶SFÁV¤KÈv7¥Ò¦Ø=M©­…ËbéNZFLÓŠU©\D;Tv¥ÚXtâŸå×4  0*ÄÕÈü¯öZ_,ã§àÔ İÖš%¦BP”›Ò¦ò½_±­H‡”ı‹éJ±ãÿ ¯JTÕi’1”ÈÂ œ‘R•$r)***""\r" R"***(&Áêj“°"=€ğ:Ò˜ÔÈ‹š~ÁêjÔ™v+(#¨§ OJŸbĞQkE2Z!ØŞ”loJœ :S•A5¬eblŠÛÒ€‡<Õ­ƒÔÑ°zšÖ2‘]bÈÎ3ïKå³úÔû©£`õ5ª‘;v§…OØ=M(Œ¯AV˜˜ÂŒF¤1z/ëR•#µ>†©H›‘y?ìş´y?ìşµ.¡¥OZ|ÈD>Wû?­9ST»©¤òÇ©£™”˜Ğ è(§ì¦–©;”5“HÃ)***""\r" R"***(OÎ)
‚sZFH™£ËİÈ­< 4õ@FkDÉ!ò¿ÙıiB0*mƒÔÑ°zš¾aİ‘”àSv7¥L#Ç8?Z®®C±½)Bò*_,{Ñå{µ!]ì_JFA”T¡6óƒøÑå†<VŠD¹ìoJr3‘R±ØÓ– :š´ìK‘Rz
k£g¥XØ=M©«Œ…ÌVDÏsOG TÛ©£`õ5¬dI Ç"ågøZ~ÁêiÊ§ ­ä^Wû?­?Èlç5*¡¡§„ Õ&È‡czQ±½*m‚ƒÔÕİ…ÈDœ•ıhò¿Ùıj}ƒÔÑ°zš¤ÄîAå³úÑås÷ZŸ`õ4ÖP1Š´Ù.ZˆÈè)L|u§Qõ«[äDÑã§åL1rGëV#ß-kHîĞˆ!FÆô©¶SFÁêjÉ»!Iæ"ã§ëO
"—Ò­X—!¡	ëNò±ü?­<(^”§‘Šµr\ˆ¶/¥Ò¤Ø=M©ª'™‘ì_J6/¥H¨AN*GQT¬'+ì_JZy]Ôy^Æ­åqA4»Ò«‘È¤+ƒVdŞ£v/¥(A8 îiË§çT®K•ˆØ„PJÑ“ÆieOCZ$J›µjP„õ§àúpAZDØÏ+ıŸÖ+ıŸÖ§Ø=MX÷ª9•şÏëG•şÏëSù^Æ”G´n¢âsĞ¯åvÛúÓ–?ÿ UJT´ cŠi\ÍÊä~Wû?­2:
z
w”ç¡«!ÊÄ[ÒéRİzæ#ÔÓAíloJrÄqÊóRª1§… c4ï`ö„!zx‹Ÿ­Iµ½éBÿ ×§qsÜb¡=iŞWû?­Jÿ ^°zšwPƒÊÿ gõ£Êÿ gõ©öSFÁêj”™>ĞƒÊÿ gõ¥‘ĞTÛ ~´İ§ÒµÁí( ò)Ôà õœ«0çI
¶)#<
°«À¢€ö…q!ZP‡<ŠŠwdóÜ‹hÆ)***""\r" R"***(Ò¥Áô¥Áô5Z‡2"
ANUn™Å<)4üÔÕ&ÉuÇ	Ïò¦ç4æp¤Ü;Í~¾ãcı¥tĞªÌÜàSĞóLVNƒùÓĞ¯¾µ(ÊT’NP{gñ¦«.yæzt¬ÜQ“§.>¿…Iœ)”ıÚmíŠÎINš§×J® Á¦|£Ò€yâ²hÆT¢JyõÎ9¨Ñ€ÁúT€äf¡£A!éÖ1ßô¦#Áô§VN&R‚$‡4¸aØÓAP{SÃ’qPâŒ\‡áNRsÁ¤sÔS×fG6FNœG ÉäSÀô!Q8§©Rx“F‚LXĞ}©á@¦‚AÈ§ä†³{™¸«
( t$€ƒŠpeî¿¥fÒ1q1äT€‚‘H#O]¸Ï¨qFr‚sjEáF})ªË@úÓÔŒdŠÆQ1qC„dÿ õªTR?úÔÄ“Ò¦Y§…bÕŒ%!R8Æi *r8È¢“ÌÏV|¦.	V'¨üEH§ b£R1Ú˜Àõ¨”QŒ ‡®îß­?Ş˜Šz°ñÍdÒ2•4*®êg®3MVOJxtYJ(ÂTì(99ÇçR!ÈäS×Ğ~4õeê1Y4c*d‹‚8§¢ŒnÇ4Å`0FµHcÿ ¯Y5s'=:æ¤R;¯éQ, ‘dP+'dà‰cöí¤v¦Ç*Ôñ0Î*L]4÷ÔÂœ¨3Êş”Ñ"ç"²ŒóŠÉÄÍÓCĞ Ü
}0Hp9d\ÿ C‰›¦®9A'µJƒÈ¨Ä‰RG2“‚fÕÌåM'‘N¦ù©ëGš¹â¡˜8+"¥ŒäŠ‰zâ¥YpOœ¢e*d€g¨?…8P)©´¢déX¸ØÉÂã€õ¤
[¥5]Xg5$l§øECFNš!ŠpN~ïéNÜ”»Æk6®`éˆ¨AÏò§`úRÈ"$sY½L¥"®O Ó•0r3H% ò)é*ß•dãs'Pc9"†ızbH;Ry‹ŒŠÅÄÊTÅïÍ9N8zb°n†œ¬QSÊÌ%Mu'Š‘AÇJbH c4ñ.¬åc(!Á9Í=ŒĞ².>`:SÑÔô¬\Lå=€éNÚ})€=A§?Ê³’f2‚Bm=Å9Tg ~&8=ièÃ8â²’fRĞôS€)***""\r" R"***(H`)±¸piûĞr:ÖLÂPC× úSÔœøÔjêÇ¥V ö5›F¤…TÉÉÍ=ãÖ€ÀqÁ§†\qÅc$Ì\Š˜<õ©Q3Zb²ƒÿ ×©Q×Ú²‘”©±BsR"8Ï‘øÓÕÂò¬Y„©TàT¨pi‘º:t©QÔœùVM3	SA³"0É :‚•]3Åa#	BÂ„ª„(uÎôd5–ÆN"nâ¤B;zR«©ïO¸à~U÷1’‹Ûò©	ƒJŒ½Hñ"Y;˜Ê(bÇ’0ãR¢0ãL)ş`ê+96a(‚£œS‚üÂˆ{SÃ¡íX6ÙŒ¢#)***""\r" R"***(ŒÕ*ÇĞşTÅ`¼‚*T™JóÅCLÊQ#ïO1ŒäRE"zÈ™äVM4a$†˜ÔÒùcŞLP;
‡s	@`Œƒ)***""\r" R"***(=c'­8:´ŠUu\=¨w0”EXv=*E\õÍ"2ƒR£ 9"³wFĞ@„ÓÑOCëO.…@Å”*nÌ%«)***""\r" R"***(ƒ§F¤ i€9şµ"Ê×›¹Œ¢.ÆÇjrÅšptôäuê1øÖM³ XñÚ¥ãø:h•3Ö¦YfÛ2”=1ùS|¯cSïĞQ¾?AI\ÎÌƒÊö4y^Æ¦óĞR4‰ƒğ­2"Ì‹Êö4y^Æw¥¤âªí…˜ÅB:N	Œæ‘ê)w¦9®7Ã´Öˆg€
“r€GãFG¨­UÅb0¤`Ó‚9Í;#ÔR3®xdØ6SFÁêhÎhÈõùY-\M‹ëK°zšPÊ:àĞ\uãğ«I’ĞÖ@i›4ıàñKòûUÅŒGƒœv¡§å}hÊzµI€Å\œiŞX=3N)|Ä*Ò'”g•ìiB0§™(ştbÕ«ŠÌLCF¡§½.G¨­"Ä3ĞÑƒèiû†1‘Fáê+Nk÷«¹§„&”<yûµ"ºg¥Z“$fÁêhòÇ½H6uÀ£äöªM±6À˜şÒ”GÂŸ‘ê)U“3LW!1sĞÑå{Ÿ|~‚ñú
wb ò½zş>øı#Iqli²+ØĞàŒÊŸæ¥bšÑ6=XÏ+ØÒ… cO9§ĞV‘l’0¤ö§y^ÆŸ½AG˜£­W3¥òWû¿¥*Ê™ÇZy‘*“dKr3ö…HâŸ¸g9»Ğ}à*”š"í2Æ)***""\r" R"***("¡€jf’<t¦yŠzVÑm†â*ç­;Ë¦h	ü)ÂEŸ…]Ù)***""\r" R"***(Œ°äSdj›ÍR8QIòõâ´‰:¢?,™£Êö5&Tt"— ñšÙ1Şäk?ãOXñÛô§¹È§)•i±;ˆb”(dzş´å TÈm*	¤( ã4ödÏZFuëÇáZ§q«‘í>”¸>†¼zO1j’Ômè&¡¤([¨4ï5=iwCV“!²?+ØÑåûÊŸæ ïJ]JàkXÜ–Gå{FB*O5=hŞqVMÚ"Áô4'µK¾?AFøıZL|ÃV/oÎ"ã¡¡e@işjzÖ‰63Êö4óØÔ‚EÏ"È Õ$ÅqW±£Êö4ÿ 1=i£<T›dİ Ø@R$`ƒNgÿ ­K¼z¤™)***""\r" R"***(»Œ
GEı)p})***""\r" R"***(;xô4	Pu¢L›±¡¹”G½O¦84Ry Õ¤Èrb¢ş”¡OLRïQĞR‰ =*ÕÌ[PŠPƒæŸæGè)wÇè*Ö„óì¦œ#ÇğştàËéÂ¤FŒuª“"Ú}(T9Î;Ôä.sŠ0=W1<Ã0})***""\r" R"***(Y#ŸÖŸ:š7.1Å$ÈˆÆç4,@ğ)***""\r" R"***(HpzNR«ÁZµtC“±ûSÖ6<N¾´ğèER½ÌÜ™FGU¤	“÷J›|g©o‹ÔU™ŒX‰êiâ%Ç"¹}iÁ“v›%ÉŒØ=M8GÀ<R†LıßÒOP?
­Q<ìnÁëJPvCùSÁ@sÅ.áê)rÜ9ÙAİJo–=MK•õ|ÕqD¹20ƒ4ìCOR€ôíÉıßÒ¬vE°·QùÑå‘Ó.äşïéFäşïéT®ƒCzš8õ©.8¥ÈõDº’"ò½WÖ¥qK»ı‘ùSI‹ÚHŒF@¥Ø}jPTŒàP6gœVíÁúôñÏOx®¾ß…hNlü^f$çs“MóqŠ]êzWì-Ÿí¤¤<>[¤F9¡5"0È&±‘„™ $Šr±'˜'§)ÚsŠÌÅÈ™YL¤¯J­ƒ*o3Ú¡œòc‰$äÒ†ÀÅ3Ìö¥S¸gä9E–95 r*(ÎÑœS¼ÏjÉ½L[»%I<âæÓq)èØçjZ¹Ô™X·Z~ü ¨•¶ö§‚JÉÜç‘"‘‘ÏëR®Cš‚7ÚzTòqŠÍ¶a)2Â6x§
rj(ß¥9›pÆ+'¹‹“%ó3Ò®£½WS´çøäñRÒ3re•` ’)wâ£ó=©CƒÖ±{˜·©*È1Æ?rÉ“Ú Ş	Å=[ø@¨‘œ‰²O¥>7
£t¨ƒ£ªÛ1Y»˜9«g®)âLúTğ1Š‘;ÖR³3“$ó	lÖœ89¨ÁÁÍ8>N1Yó+©ºP£t\SÃ€k6sÍ²]ãĞÒïúÔjÙ8Å-fÌ®ÉCÇ5 b8}êjÊFslrÈr3R	A8şµ)***""\r" R"***(
ps•›W2rĞ²²qR#åy•WY8T‹'Ê8¬¥nL²àô§		ô¨ÿ ³úÓ£“•FL²$Ï¥Iæı*´ruâ®3øÔ³hXYëOWÜq‘UüÏj|S( YJ&m–Q¹ÛOE@²Œçÿ 9k#I’«‚y"$ ğsøÔLŒâ+6Œ¥&XÃ©Í(ƒœT{Æ(ó=«6Ìœµ,$ã¥3sUÕ³Í=_±üêlˆ,,¤I§«¹ªèãŞµ “Q$ŒÙeeÀëÚ¦J§x©#“Ú³”L^…¿4ç©§yœgŠ®X“‘NqX¸™I\›y>”äğ*“ŸéOI>n•)***""\r" R"***(H˜±#€ÄS<Ïj<Ïök&µ3dâL§+)***""\r" R"***(AO¥CHÊL™$*y9©`ÕX6Gm8Åg(œóeù8œŠ…$ùºSÃâ³hÁ²ucŒûSÑŠ•“Å<J ¬nc)2ÈÓ·Œäœş5^9¥Hk6Œ¤ÉÕóÁ¥5ÈÉ§	8²’2l[E805ÈÓ„ dâg$‹
ä™uTY?ıU$rJÍ¦dÒE­ç¸§,¾ÿ B%)***""\r" R"***(Úœ$PsšÍÆæV&ÏTªF95XJ SÒA€1XJ&-–D™ OITñP#Œ{zÓºÖN&2-,„*E“š«ñÒ¤I=«&•Œ¤¬Yóµ*È:Ôeò1Š@H¬Lçz“‰³ĞSÒSzUo3ıšzHÇJÍÄÊI––@9§¤Ø9#òª©'ÍŠzJQY¸óW-‰oÒ%Ï¥Tz~´ÿ 9}+9DÂH´³Œc4ôš©¤½ªD“iæ³pĞÅ¢âËÜ
x”õ¥UYFsŠ˜1•¬\d‹BQOY7ëUVPxÅ=dU?ZKJ%´õ"Ë¦ª$€sOĞÖrÏ$Ycø¿ZwšO"«	”œbœ²àò?ZÉÁ4Ë)<S·ŸJ‰f]½)Ë*µC‹1™2¹Ç¦I
÷ÍUYNië(äõœ sÊ%Á Ç_Ê€ãT(Zp”‚£‘œî(œHGCOY³ÁTIÏ¥I `jä‘dKÇzrÊzŠ®%à
rÊäVn1•Ëk #“R	ˆ<UU³ĞÓÃ¥fàdÑcÎ©?pşñüê{“I½}hå3å'ós÷Mkc Ş Ò¬¤sùÕ¨\‡o5ıiVF'¨¼Ïj uı›&Èœ±îhÃçUüå¥û@ÇZÒ1°šEçĞQ¼ú
®% £Ìö«Q'”ŸÌ>Ô†lb¡óè?Z¹õüj”âN%Ï¥'ŸíPùÔyÕ¬bCH›Ïö¥óG·çPy¢”ºã­_"%¤MæûŠ<ßqPyŸìÑ¿¾?Z¥HœÉ2?
2}MB2=})şgµh$‡äúšLó=¨ó=©¨Ñ%§ÿ ¯K‘ê*3Ú3Ú¶Q%Ù‰1ÜQæÓ™íG™íG³'N„şo¸£Í÷ñ”»×Ö©FÄ´XÄÓÖ_Ê«‰8« õÅZ‰)***""\r" R"***(X³ç¯ÓëAqÔUV“=)ù­I²,}¥¿È NÄàƒÌö¥Y 9"¯•ŸÎqŞƒ+õœ´yËM@,‰|×õ¥2ğzÔ>rÒ4 ô5J0•{šU™@ÅWZQ"ƒœÖ±€D¹éŠ_0ÍVóÖ—ÍÈî~µj$5bÀ•sÁ§«~µWÌö¥óO¿çUËqr=E/›î*¿œ¹¥ó=©¨	ØœÉâ“û_­Bd’(Èq€»nÏñ~´Ús‘Pùƒ¦(ó=«hÄ‡7ÜS•³×[9Å9fÇZÑ@N%ç×?aôs/<S¼å¦¢CD»Ï ¥Vã9¨|å¥Èi1ZÄŞxŸhÕ8Ï&“zúÖª#å¹gÏö§y¯j°™@§y§ßó­TÊNÒñúÒëŠ„Ê{ş4†@H«Q°4LfÈéM2·sQyËApã¥h¢î$™'›î)Ë)<gõ¨	­7ÌÁà~µ¢‰qE¬QFÿ ö¿Z®³`ÿ :rÊ­Vš±!|
pbÃ­E½}iVUQŠ¾R%Ï9hó–ª;“f?$t4àäEEç-rÕ
Åä÷¤gœŠ‡Ìö£Ìö«IƒD›Ï £Ì=…Gæ{Qæ{V‘‰$aµkúÔ{Æ?¥gµj’!Ä“ÍZ¬zâ£ó=¨ó=ªÔu‰*¸=)ÂLt"¡ZPÀò)***""\r" R"***(R‰…Ÿæ¢`NÕpäy¥Ğ~´ÒÔÍÓ,o>”õ™qÒ9j¬O)`J09¢P~éªşg·ëNI@ê*ÔHq,ù¾â7ÜTÇaG™íWÊCDşo¸£Ì>Õ™íJ²àò)***""\r" R"***(>QY“y„zR¬ø<ŸÖ¡iU†)7¯­>R]ÙgÍİß¡Øg?Z®²uç4ôœä~´ìÌÜI·ŸAFóè*?3Ú3Ú©EfJ®HûÔñ+*¸“ŸJzÉÇ¯½ZD¸“‰ıE8H_Ò«ùÔ¢AÙ¨q%À³¸úÓ·ŸAP	;ô¡¤Éõ¦‰ädûÏ ¤óµAæ{Rï_Z¤…ÊN³ÎißhÕ[zúÑ½}jÒ)dM“Š_7ÜUd“ÿ ÕNó=©Ù’âÉüßqG˜OLT ƒÒœ$	ÁªJÃå%/sŠpl)***""\r" R"***(W2)9Í85IàYc¸£Í÷ |b3Ú­DÏ”œHO¥8LAäÔ œdSÃ©?0«³d¸Øüg,iq)»ÔœmÍ8ps_¬]íl¥qê¸ëÖŒ8Zxô4å#;³Y6e'bU;NqNVÜqŠŒ{ÓQÏ5&2‘"¶ŞÕ"¶ŞÕ:ŒÓÁ¡¬Û2lzÃ8©â¢B äÒ‚È¨lÊR&ŒS·Œd
dl£¿4ğS95œ¬e)Qº)Ôğ)F;æ³r2rC•JƒNÎ9  zö¥~½*F2b¡$dúÓ×ï
b0{ÓÁÍCjÇ<ÉÑ±À<Óƒ`æ¢G]ÔíãĞÖR2näÊt§€AQÇ"§µ<H¦³nÌÉÉØ8¤gcÒÒ©Áë6ÚØÉ±S§ãR+@ÇãLÜ àS”Œæ²m³6Ğü’0jD;@8íQdzŠxqŠ†Ì^äªÛ»Tµn9©#Vr1‘98¦ïÏÚ5‹¹Ñ*ıáR¯Aõ¨E*e‘09¬¥±„ÇÒ©ÚsŠg˜´»ÅA›Ğ>õ sPoõ e<ÖOc	Éó=©Tç'Ş£Ş)ÊàÇµA›m§ÀÆ)Á 0<f¦F2l”ŒÔˆÛGNÕàT‘ò3YÈÉÈ˜œT„àf¢ sŠy‘OœŒ$ÅYriâ\B89§†¥K1oRdvb	?…H§5>ÑNGÍc(³92Ğ“Å9•X0' T©"ÖRFE…|ŒJ­1Q£K¼zÍ¢¹:H1NS‘œTHÃÍ=dP1š†ˆv	Švş9ÀêijlfÙ*>9©Dœô¨†1š“x©’3‘?™íFñ•˜´	œf±”LY2IĞ~•"¶9]XœÓÃƒÅdâc$Oæ{S‘Æxô¨OSR# sPâc-	êJ¯‹Ğš›ÍOZ‰$sÍ/·ŒÒÆàñïQ<ŠOèœYµ©‹e˜ß§ùÕH»©áÀ¬šÔç–ägµ=ªËëOY¬Ú3l°$ÁéOÜŞµ^9 5)pF+'õ$Ş1ŸÒœ’ãô¨ˆïOW¬œLÚ,$½éNó=¿Z\gÖ•dMß5fãc6ìXIOOj’9qUãuÏµJŒzÎHÊL´„œäÓÃ‘Ö¡Iu4íê{VMÉ“#÷Å=$ù¹
:…èzÓ–E)***""\r" R"***(šÆHÆLdÁ©ÁÔ
ÃE<8™›I“£b¥CÚ««®^•2°=+)E˜É‰yï9É¨‚1ŠEm½ø¬\Z,	8”>N1úÔ"ƒS$‰ŒÖn&Rd…Èšr>ê‹ÌFíK¼zS	jN²2ñ*O3Ú Ş3Œ“zÔ8M’ ğiâNzTÖœ’®95“†¦,Ç&Æ¦F8Îjš?BåR¬«µ›“Eøê?‘éÅUIW=j@àtjÍÀÂH²­·¯ó§0x¨#•Îêw˜•“”‘2ÌOZp”‚ Y74ÿ 1OJÍÀÉ»\€rE=dçÍVI ç4õ‘OCPàe$YAĞŠ‘%QÁª« "’‚pMCÍ%rØ“)***""\r" R"***(*Éß­WYM8:ãp5“‰Œ YzŸÒ”IÇJ®²©šrÈ©q0”K*Ç¨©nÍU•ÇcR+ƒŞ³q2iUû©©¤ƒš¨’*œnúsR‰ò+7™I™cIæsÒ˜\M'š”r3&¬Kæàü´¢cŞ¡óSÖ*õjµr9h3Ğâ«´ŠF¤È=)***""\r" R"***(W))***""\r" R"***(î_Zr¸ÇÕu`½E;rúÕ(Ñ?™íG™íUüÁèiwCV¢"3Ú0w piË"ŒÖŠ,L—Ìö£Ìö¨üÔõ£ÍOZ¥A'™íN'5š™ÆhóS8Í\`'bU”ƒŒSüÏj¯æ§­jzÕ¨bÇ™íA”¢ ©¥Ç¡ªP%«“yËGœAPï†•$QœÕ(”[wj¶œb™©´3«æ´I’ôæ{SÈÍG‘ê(Î{UrÜ—•Iê)¹AÚ—xô5J"jãÃôàHéQo†…“ÓŠ®VC‰;8ÇáQ—…5œg“Mó´QbåDgµgµGæ§­jzÖŠ7)'™íG™íQù©ëGšµJRPIê)Û˜÷¨|Ğ{šÜrjÔ!`)„P¼£ 4›Ç¡­TDZ®94¢Ojª­ÜSƒñÍW(š¹cÌö¥^*¾ñèiCã¡ëO”\¥¡ =iİ*²Éèqõ§ù‹T¢&¬H\vyÕš´y©ëT ÉJÄg·ëJ²€rED%SK¼zÕD,™:Ê­K½}j¸™§, õ5|¢å&Ş¾´gµGæ¦zÑæ§­W+DÛRQ)sTBE<ŠPàš¥Y†,2iÁğ1Šƒxo†¶ŒOæ{Qæ{~µ_x÷¥·ÖµQ3Ûõ£Ìãâ£óSÖ5=kNP$ó=¨ó=¿ZÍOZˆyÍTbKDgµgµGæ§­jzÖ–dò’yÔ	Hè*?1OJ<ÅÇCô«Q*$2“ÔPg‘LŞ=)***""\r" R"***(Ç¡§a8¢PİÁ¥,OSP‰x§‰9§fCŠ$ŒQæ{S7C@aµ¤b&»Ğj5dÎ	§ïQBQæâ3Ú™¼z7CZ%a8¤?Ìö¤fÜ1ŠÜL.cV‘.$ÔT[Ç¡¤ó¡­"ˆåE3Ú3Ú«ùƒ'¯Ò—xô5­‘Bc*‚hó– .§¨£rör¦K‰dLqÅ8L03UÖEÚ9§­@—–7æëµÇz~áµj63pD»ÛÖ—Ìö¨üÅjzÕYfIæ{P%# ıj?5=h+p)***""\r" R"***(RW™/œÔå—'®j,QFG¨ª²)7™íNWşé¨À©ÕzšiÒ%W óR,€Š¯æ)éJOSCD8“‡éN‘P‰f”0<æš‰´ ‘ĞÔ;‡­<8IX—`HéNó=ª.:Ràõ4ÔÊ‰ŒœzS©9ÍG¼z7CW*CÄ˜9—ÎjŒ:šPÊN+EåD«/n´àAéQNÂœ’(Îiò‰Á‡#¯4¾g·ëQ—VSI©£–ÄòØ›Ìö >O" )***""\r" R"***(=\`
« &ÎyÍ9\t5¸—xô4Ò3hœIÀâ€àÔ‡­I¼U¤C‰øÙœsG™“Æ˜Yz¨¯Ô[?Ú"E'wZ~Hã591ÿ ëÔ¹¶H¯Î	íR!$õíQmÏN½ÅI¯¥D™Œ£ò}jT MD¬	È§‚CYÈÊR$	Å.üf£éHa‘Pa&N² :šr¿sš‰@š‘F)***""\r" R"***(fÚ2nÄ¨êNj`ã«  äÔõ#¹5‹0l²‡ÔÓ¹'­C'95)`+7¹”¤; wçÚ”Ï=>´ÑÁğÀœPÙ‹wœ„“É¤UÏ'¥8(fÙ›bäúšz;e*3“PÈl˜9n„ÒäúŸÎ™¯<ĞÍ“Á¨½ŒäˆïNYyÅD¬1É§›¥Cw2“KbQ!>”á'Ö£QŠZÍ™JEˆäP95,nj¢Ï58b:VlÂR&ó0q¸şt1ÜÓ	ÀÉ¤Ş¾µÆL•_œçğ§‰2@Ô
FA©#eÏZÎFRdÊş´äÎj,Œg4äaœæ²2l°’g¿çR‡ÇŞªÑ¸ÏZ›zúÖLç˜ıãĞÒù™¨÷/@iF3‚i;^Ä±±biã"¢R nièÙ=k6Œå"A œÔ¨Ùg¥W	ÆjDn85&2&VÇSNŞ3Æj0ÊN¥¬Ş†r$ÙïO	À¨A9ëNÜ`jŒ‰Ã€9Í(|3QÁ4ô çµg#&ìJŒIÅ?qõ¨wĞÓÕ½MfÖ¦nE…r:“NÏ5 ô4ä`)***""\r" R"***(CJÄ6J¬HëùSƒyéLG\u¥Ş¾µ62“'GS²}juÚ9§,œğk6ˆ& Å89n„ÔA×šz:š–‰iGZp`yÍFX‚h,Á=j¹‹&Y1Ş¤G$òN=êe“R+.Şµ›Z¶JgƒOñŒŸÎ¡‘J„ÍdâsÊDù>µ.ãëP+xÔŠŞ¦±hÂL•_<z0T—<z¸Ç&¥«É«sš”8Çz®®¡zÔŠêT`ÖRZ˜ÉÜAÍ?x)***""\r" R"***(E¹}ik+¶XVÏ"Ÿæûš[®ÓA|¨hÊI2À”g’iÂUìj²ÉïŞ½}k6ŒÚh²CÎœ¬[ƒPDêHùªMà)***""\r" R"***(D’3z“£•<š˜7÷MV¸ÔÇf¬e&ZIæœ² zšXÔ»­bÓ¹”‹Be^ôñ"š¨­µ$L2k)DÎIVLtıiâNœš®©† Ídâa-QÈç5$rõäÕD|pZ¦VàÖr‰”‹QI§yŠzT—j¹±q2jÅ êiÊØ9ÏÈ¤g5":íëY¸™=‰ùæ®É?­C½}hÜ¾µ§4‘d9#‚›îj²9“Rî\õ¨k¹„‘ —¦®Z†œŒ çÖ¡Å=	ÕˆåM;Îã«‰÷=\c“RàdÚdé6{Ô«)îMWVLdÔôpxİY8ÉQÈïRùƒŞ«+`šq|¬ÜŒ‹NùüéV\Õ_0xÔ‘:œÕÊL²²x?8Hs“úT(Ã Ó÷¯­dâc&L²ûşU"Hşu]sœÓ·¯­C“±id©£Í ü§õªë!=iCärk7LÆV,¤™èÕ,OÆ	ªhà7¦I
œæ³•=yÕÏP:p“ÍWŞñR‰@?{ó¬ùy$Ùe\ö9©#”zª‰ äzH½C…ŒåËKšnòzÊ¡2q÷©™9ÎMR›‰cq=õ¥Wçï~µåÒœ¬¤à5>BZ±>ñèi<ÕñQdç†¡[“G),›Í÷4y¾æ£Ş¾´'İkEO+%ó€=M8J¤dšª\w4o£Uò’â[óSÖ1?½UÕ×šBäğ*ãYgÌZBÄÿ õª¸'<µ8H ÆãV G)6æõ§o† Éõ4 dšÕ@MXœ:Ñ¼zƒÌŞ4yƒûÆš€‰üÁÛ4	2~ñüj ÄŒ†4¹>¦©SDû÷¿Zp`=j°v)***""\r" R"***(8JOSV E‹`3G›îjps–§o_Z¾To¹¥‘ëQo_Z7¯­¤ò²q0Æw~´¾pşñüê¾õõ£zúÕ(\›2Ç›îiV^8?VïT›—Ö©BÂjäÅÏ\şTß3=I¦?z“zúÖŠ"å$Ş´ŒùS7¯­#ºj”uĞâÄëIæûšx=ZëëZÆ$5rd”ö4¢CüUğ:5)bI­A"}ãĞÑ¼zƒÌŞ4	3Æê®PĞœIÎ4íÄŒgñ¨U† 'šz°ƒO–Á üŸSN u¨÷¯­×Ö©&ÆIæûšSpMD=)***""\r" R"***(ÀqqZ(Ü†‰|ÿ j<ÿ j¯¸úš7ï~µ¢)***""\r" R"***("ÊË’)***""\r" R"***(;Í÷5^6P@-ÍI½}jÔI$óxÎMo¹¨÷¯­×Öš‹@H%Ç¯ãKçûT[—®hŞ¾µª‰-	ñÀ4á/MWŞ¾´yƒûÔÔu‹o¹£Íç©¨<Ïö¨ó÷j¢Q9— åG›îj Äò)***""\r" R"***(?zúÖŠ7&Ì“Í÷4yæ£,¸àÓr}MZˆ­bo7ÜÑæûš‡'ÔĞ¬:—ü*”DMæûš<ßsQï_Z7/­h¤˜ş#Nßw~µ¹É§““T­qşo¹£Í÷56OŒŸSWÊ.Rpäóšw˜Õ]]‰ÆiÅˆêÆ©@\„Şp[õ¥ó}ÍWŞ¾´àä*ÔGÊ‰ÕÈèsRoÿ kõªÅ—vO©ªP%Åy¾æ8xşuO­!eÕ(âNfp3Mßş×ëQn_Z7¯­Z‰$¢LëFÿ ö¿Z‹zúÑ½}jã\	wÿ µúÑ¿ı¯Ö¢Ş§½×Ö´å!:¸Ç'4»Ç¡¨qÁ§+`j’%ÆÄÀç‘J§“Q{K“êi¤.[“†Çñ~´oÿ oõ¨2}Mˆ÷úÖ‹rK&VÇ&›çûTe94›×Ö®Ä8“	séJ% äŠ…wu§ï_Zh‰+	‰8‚Äõ¨wĞÓ‘»“V‘)***""\r" R"***(‰ëúTŠÿ Ş¨7¯­=d©ªKBIC›©êãœÔ×Ö•Xãå4râO¼z˜îjÇÖ•XmäóMFÂq&O94á#ŒÔ!84ğËMR‰.$«/¿çOŞ=)***""\r" R"***(W ÿ 8³Ö­Sl›X”¸#ŒÒdúš'ÔÑ“êj”™&O©¡[’j5c»“Å;zúÕr*8>ÔıëïU÷ĞÓ‘ÁÎZšˆšL›xƒùQæ×5åëš7¯­]ˆq$§½(lr)***""\r" R"***(E½}iD€w¥ÊO):¿Ë÷±K¿ı¿Ö ŞXP­ƒÉ«Pbå¹>ÿ ö¿Zwšşµ ô4¡ˆïŸ­_).6?©WÎiÖÁõ¯ÒÏöYÈ’œ„cæ™œô4ôQ×½fö2r	)ÈI<š@£»SÂñÀ¬›1”® ‘ĞÔ¡°0)‹<Ô…WÍChÊRÇ&«Ø
E t4ôéøÔ·sÇÆ¤OPM5O R ¿5Œ™”Ç(8Å*¡Æ¡“Ú9èk&ÙŒÛ “ŞÏCH98%ClÁ½B•>ğ¤¥_½PD‰ˆ gŠvõõ¦CHHşõg#õÏıÓB1n¦›ZrwÄä<63ŠUoSM'§*sÉ©r0”®8c<šz *f9Æië€1‘PÙ‹cÕÆ>cK½}i€p)Ê«ëšƒ7;GÎj`Àô5îìjT g&³v2rC÷1ïIFG­! w¬›±›c•°pzSĞ¹¨úô4ğF5-™I’¡¥”Ä#9Í>¥ìdØø™‰ëSooZ‚.µ.G¨¬™”ÉƒNV¡Ü=iTójLÅ´LîäñR+(QÍ@É"‘·­KV2‘&õõ§£r~• ô4õè+&Ì›,#6sš–¡Nõ)`±‘ŒŞ¢”ªFsQÏ©W5&-Ü˜0' Ò‚GJb“NÈõ·3–äŠÙàÓ#¥F„É§dzŠ–¬Év'IxûÔ¥Ãµ$ÒäzŠ–Œî‘0b)Â^>õA¸{õ¥Gç¨q!–\¹§¬„)***""\r" R"***(W©°8¨q3e„~8?Z•d÷ÍUz2Æjldö&”´æ£Î;Òï$ZTe%tJîäñNqò*sĞştõÀl“Y8´a$É–Lu§«ƒÖ¡È=)***""\r" R"***(<Ífãc)¤€õ5"HäÕxÈçš‘p3–g(İÌ—rôàÄt5G­9“Ş£•²Tö¹§		ŠÏZ~G¨¨”Q„›®sÓñ©VBG¢`sK‘ëY4e$J¼Ó‹ÔÓõ§0SÎîÕœ£ØÅèÇ"—{zÔJFáóT™¢±jÄIG9ÅJ²œ`œT óiÊÄMKI˜¶XÉ<zzT©!P#…GJz¶zÖM+ÉÜ²¯èjE“°8¨c#iÁ€<YJ:µrtSÍ=\ƒÉ¨²9"¤‘X´e$XF:óNEB¤ŒŠ‘HÀ›‰‹'Gã“R#‚95@çµ>29É¬å)lMægÔ àæ˜ÁO Ó_Ö²p¹”‰ÃŞÔá!J®	 Ô‹!ÛÔTû3	"u“Ôàç®jpİÿ |gk7	+V@G-O)***""\r" R"***(»ı*°|t"¥V#¥fàc%¡2É×¾oûU›î(2sœñY¸´N%Éûß…Hvà•]lf¬£Rå2‘eã óŞ­‘Ö«£zÔïY¸˜Jè±æ€8jvöê,Z{ƒÏjÊHÆC–@iá»ƒUÆ3ŒÔ€9Vn&M“¤ÄpÔá>sUÕÉ<)àƒĞÔr£9$XYYºSÒB8&¡ˆ^ÔüQY´bö'IïOŞIö¨2:æ”>?ˆTò˜KRÀ=Á§¬¸ŸÒªù€çJ’97u5›‰Œ£bĞ™±J$'¡ı*âœc­fàfâN²0©QÃôªÈİ‰úT±­Ë}êd¬L]€Îi<ßö¿JBF1ši\w(™5qşoû_¥oû_¥GE5	<ßö¿JÃ<š#ÔQ‘ê+EÔVDáÁëÅ/J®S¼ÌR¦KV$f9ùMwı*"äuj<ÃıáV KDÁ‡vı)|ÜD¬1ÉõŒ“V K½z7·­&G¨£#ÔU¨d89iŞfˆTy¡£ u5§#!Ä~åõo_Z#ÔRäzŠj,T<:ƒi|ßö¿J‰œšo™şĞ­r¢ÂHV§o_Z¬²‘ÜrÊOSO‘ƒ‰1
O9j2ÁE%RŠ"ÄÂPz
Q1TH@š\¯¨«Pˆ¹I„ŒFs@r5|pR‰=H4ùr“\u¡HşQ†ëJ=)***""\r" R"***(>R\lLdã¥4Èş”ÂÍĞšBGLÕ¨»ŠÉŞ¾´n_ZfG­µ¢Ã™¸ùM&öõ¤ÈõdzŠ|¦lzs“KQ‡ĞŠç5q‹¸Zä”…€êj<ïRäzŠÑA°Q$ 0ƒ7ûUG¨¢´P)***""\r" R"***(‰<ßö¿JPç¿5<ÍR€¹‘2Éù¡¤çÅEz*”Q7¸æa)***""\r" R"***(Îy4ÜQFG¨­RaáÀèÔ¾oû_¥E‘ëK‘ê+XÂä·bd˜‡µ;Íÿ kôªá€èÂ—Ì?ŞjîËBz5ÛÖ¡W)***""\r" R"***(CI§?5¨¶JXg$Ñæm)***""\r" R"***(PrzÎ7ÜUÆåÓR7ı¯Ò7ı¯Ò¢Îir=EiÊÅÊ‰<ßö¿JPäu¨ÀÏqOÈõªQK½½h,HÁ58¥3{zÕ¨‡)1a)***""\r" R"***(7{zÔ{ÛÖ•Xç“Z(‹•’+y4àHéQ†£
r±'“T‘-"U“ñO2qÀ¨r=E(pZ¥Z±&öõ¥WùEæï
<ÃıáV¢	Ø›zúÑ½}jíëNVã“V¢l“zôÍ/›7Ty¢ŒZ|£å%.Ã©¤óÚı)	ŒÓÁÆkHØMX“Íÿ kô¥ó×5Ç9§dKDÅÉéHd#©¨üÂzH_=XSŠ!­I€õjMëëLÈõVdH=)***""\r" R"***((b:b3“NÈõv!î(võ§¬¹=
#ÔRdv"šD4YY01‘Kæï
®‡£{zÕr‘ÊÉüßö¿J]íëP‚ëRäzÕ¥¨ZÂïoZ7·­!84dzÕ‰¡w7­9¿úôÊ äU%rnK½½iVFZ‹{zÓ”¤Õ¨Ø‡U‘šœ÷¨#¡¥VÏŞ5¢Dò’‚OQŠr“Ó8¨„˜î)Áƒsœ~4ùHpd»€µ/›â¨²?¿KÈëT¢‰q%zæ’1 fè)***""\r" R"***(<r*¹Q.(™[±5.õõ¨ôÅI‘ê*¬fàÇï_Z7¯­FHÇ)¥˜´íryY6õõ£zúÔ;ÛÖíëG+RpAä*bO&z¤„àL_Ò“{zÔ`‘ĞÑ½½jùQ¤›ÛÖíëQïoZ7·­4ƒ”•f`0iÂB{ş•`G&œñÈå'"œ®~µãïS•ÈëUqLüyWÜsÏíÄ3“R!ä÷¯Ñ[±şÄÉƒ*E'®)ˆFsš^A¬[¹“mW$ã(`7võ¨ÁÈ§+×‘„¤Nö9¥VÏ\T úzT½Œe&H® Š‘$ãõªôøÉÔ4ÌîË
ıò*DlŒçš®‘NÖm36îL$=8§«€8#š<š}fõ1“e¤>ÿ ­Hdì?Z®„É§dç9¬Ú¹“dÛÏqHdçsÒ…?6I¬İÌäÉC‘ÿ Ö 6ãÍ7#ÖŒZ‹\ÉÈ™2*D g&ª«`äR‡=j1“'È=)***""\r" R"***((r8ÏçQ†#  ’Nk)$Ì\›dÊÙ‘K¸zÔHxÉ4¹µÄ²UO:çõ¨”®4¹¡¨lÆL™d#­?y¨AÓÕøùª^Æm¢bqßn¾j=ÀõoÖŠÉ˜¹ÁÆ
_0Ô@sOœŒRÒÆm’,¸©Øœf ÍH„¨zT³'"_1»TŠät5
±n´ô g&¡£I’«g­=“P‚;zMCV3\ƒŠz9ÀÈ¨²=hÜGzÍîD™a\œÔ‰ æª õ©¸¨q1“.«çß­<ËÇQU‡×ò§ù¾â±”L[¹)çŠU““Ú—#ÔR²2Ø²²ñÚ—Í÷7n)r=EM™rÂKïOVÏ\Ud<òiâBŞÍI)***""\r" R"***(–U€ç9£yô±iêÙ4™Œ™"¶FM(`r* İFîş´ dâ¤ÉËRe”÷?•Hıª4àäPgÌXØ©B½«)ãƒRèZÍ¢\‹&Rz‘J²ûşUG¨¥)***""\r" R"***(úÔ¸£&ÉÄ¼õ4ÿ 0íâ«‡$óŠz¶0JÍÄÍ²q6q>´øä=1Uò=jUp£‚+)Eòh°®àŠ—Í÷UqÁ T¹Íc%c);“o=Å9eãüj&;çñ¥ó9àqYµs¬N$9íR	Iª°9æ‡µ†.ÄâSœùS–_òj¸=Á©Ï"³q2‘hHzñNßş×ëUÒCŒR™ëŠÍ£	&O¸zÒ«dãu@$$ö§¡ºÔI"…„ëÉ§äc9¨T€ Í;pé»õ¬¥LdL¯¤SÃUÃÒ¥FõoÖ¡Å5bÂËïùS–_Î¡B9æXJ)×RÀ|÷?9$e8ÍAc¿5 `FsY´fË	1'’?:‘%9ÅUƒ‘OVî+9#	V\ÈéOY²r1UA€)***""\r" R"***(H­ƒ€G5‹FNå–”úşf%BXuÏëH$5¬Å·b83úÒ¤§5sÎjHˆãšMI’ùŒ)***""\r" R"***(=go\Ty¢“#=ECŠ3–¨gÇÔ«>ÁâªS’L÷ıj1’-¬Ûºbœ¯‘Éª~fÓÁ§‰‰ÉÍC¦c$ZúÓ¼ìŒîç5Z97H§e}EC„íbÚKÓ&¤õMcéR£·¯Ò²”nsÉ]—|pM?Î?ŞUÈõ§ éúÖ\¦2E '“Í8>?Šªy¾â•fäe¿ZB.,¤OäiË69ÉªÁ²94¡füK“±m'#x©ByİÓŞ©¤„qÒ¤YPZÉÓF)***""\r" R"***(2âKÇQNó}ÅT7cJ³àrA5›…Œd‹BQH¥í<>µWÌÏ9Å=NGZ—)hZ3ƒSE)<úÕ4m ÔªİÅfâfÑud8*Q!ëT–A€)***""\r" R"***(H²2ô5›Œ‘lÏÇJa˜sQ™;)2=E5&¬KöƒïHg,qQäzŠFl­6%ßş×ë@“Ä?:ƒÍ÷y¾â«”—bÇ›î(ó¸ÆEWó	éŠUlõ"œbKØŸÍ'¸¥Ş}C¸zÒ‰1Ü~&¯•LM=dnçj­æûŠCpE5sû_­ÿ ÚıjŸÚ½èûW½h Éh¼%^Æ‘¥¡ª‹)õü©şo¸­jäÅÈ7ëIæ¿­EæûŠ<Ï¥W+TJ$bpM;#ÔTÉ¤ßş×ëT¢.RÀpA¾gÒ«oÿ oõ¥cø‡çWË ¹K"Fí@•±÷ª·š@ê(Æš€œK>qşğüèó¹å¿Z­æûŠ‡ÔVŠ™<¥¡p c?/ŸíUƒ9"œ®@À9ªäBvE•”†¤ Šªcïcñ§,½³ùRQ³-ù¾âšXuÍV2ã¹üéÄÿ ëV fâÙ`Ê3œÆƒ/¸ªÁğs»õ¥/¸VŠ$¸ØŸû_­(sÔÕmÿ í~´,›z7ëUÊ.RÚ¶zâƒ ^õ[Î?Ş*±~I¦¢Ğ­dMæûŠkJ{fG¨£#ÔV‘B°ï5ıië3cï~µG¨¦0q‘Z¨Ü,‹>qşğüéâ\ŒäU?7ÜRùUÈE±.:øRƒÎ*)Ç¤3ñÒ®0&ÄŞkôy¯ëUÌœÒ‰Mj ‘¬œHÄòiÛÿ Úıj ç<Ñæ}*Ô«"}ÿ í~´¢Lüê¿›î(ó	éŠÑCBlX‘ĞŠ<ßqP	=E!”g‚*”F“,y¾â7ÜU7ÜSƒ9"šI”œJİ<HHíP©zÒîŞıi‡*,ãï~´	 î?:ƒÍ÷y„ôÅRC²,sÜR¬™8ÈªûÏ  9ÍiÊÂÈµ‘ê(Èõ_û_­(sj’#b|Q@|wAæûŠ<Âzb«”"Uîhó3ĞU}çĞP²œş•J"å,o>‚•[#’*¿œ?¼:<ĞzV“³e¡&2(ó}ÅVŸâıi|À3Í_(r–<ßqG›î*¿˜OLRï>‚På,,¤M;û_­W)***""\r" R"***(ù¥2×¤R}ÿ í~´¦LŒdUs!î@¤İş×ëG.¤5rvl¦ï5“M?#ÔU$CC•‰5*¶zâ äKæûŠ´¬MÉ‹M,Ozg™½IæûŠÑ-É¡&O© 9›î)Á‘Uf.TH¯òıìT€Œjæ€ÀëO”–‘b—'Ö¢Wà|İ½hÉõªµ‰å&27­cT{Ï ¤ó}ÅZH—_5ıiVCj7ÜR‡ÅRD¸èOæûŠ<Ò:UüßqK¼ú
Õ"9+6=éDÙôªë&:~´íÄŒÖ®ÂkBq/=E=dÀãõª»Îy§,„ñ«Q±“Z–|Ï¥9_åûØªÂCiË/:®QD˜È¥·\Õq&OoÂ$à(°¬XråOû@öªá‡@iÅPîıjÒL‡SpzO9½úÔ4Så'•‰sÜşt4„ É)***""\r" R"***(ÿ ÛıhQÔ\„é/½;Í#¡X>;Š]ííV¢O#,ùÄŒf5»šƒÌã4kúÕ(“ÊZYxëùÒù¾â«,¤H§=Å>Qrù‡Ú&<Upü}ì~4nÿ kõªQM[Ï £ÍoZ¬&n›¿Z~şÁ¿Zµr3ò'9§$âšNM&ñœ
û¶ÏõåÌ˜9õfÇZ>ğ©€rk6Ìå"ElI¥V$â˜­“€)ÊØ5)***""\r" R"***(£M’ÇŞ¤½D«»½>¢M9R† `Tj»†sN›‘D±·Bj@Ù}áS'İœ›3r$Vjpr8¦ ç4êÍ´bÛ¹4dœäÓ÷šbtüiÕ›f2vriC’ØÚTûÂ³‘›wE@É)***""\r" R"***(Ù™¶*uü*XûÔA	ëR #9m™JDªÅºĞX)à)·•–·1r¬Hæ–š?uKÜÍ¶.æõ§©8ö¨éÊÄŒık6g)!áÈã&óQZz®*^†R‘(ã‘J¤’i­Ğı)¨Nìf ÆLzf£¢•‘ÉCOqÖ¡@AÎ;SÓ¯áRÕ‰r'Ï<SÕ‹u¨U¶ö§‚@À5›V1“CÙÙN*»œÔ}éèŠ†Œ›±"€sK’zšj±è8dF*-ÜzôJZEè>”µ“fD¡ˆéJ“)´RiŞä«œã4ú€1)***""\r" R"***((|œb¡¢$NôªÄœ‰NM86NI”™:±<T‘çœÕUm¦¦BNrjZ0m“dôÍ=2G&¢½:¤ÊNä:SĞœš€E=ç¹ndË
r¥¨”’¼ÒÔò²	2GCR†**¸$t©WîŸ¥"d<1'§Zzõ àæ“WFeŠPÄTòqŠt}Y´¬fİ‹¥=z¥B§i©±Íe%te&J„óÍIæqÈ¨·v©·v¬dŒ[H‘I#5"r95 89§«w&R»&@Å9IûÙ¨•²@"œ¤A¬å'tI“œæ¤V pjã½*Éø¬ÜLÚdáÏqNÉ=MD­»µ(89¨hÉ¢@HèjEnP‡ÉÆ)ààæ³h–®Xò Å>««c
x`kŒZ±:½©Àr* ÄSë6Œäµ'W&²08Í1:~4ŒpÙ¨µİŒdXsOY?Æ«+g‘ORHÉ¬¥H²‘œÓ–B:ÔHÍ.Hç5‹‰‹Ô²$'œT¡ÏqUAàš>õ›‰Œ‹É8âUúsK½½jL¥€Äw§#İ*°‘Îië&@8©q1”Ygyô›ÍAæ{S–BF©²3dşo¹¥Y	éúÔ!ÈëÍ:¥ÄÆWDÛÏ ¥BHÍD÷¥Wù¸üéXÅìL¯CR,ŒFqP©$dÓ•ğ1ŠÎHÆM&N­}ªPçŠ¨g)êäsœÖN&W-¤ŒF)***""\r" R"***(;{Í@­@§™8àVn&Lš…,sPo9æœ®2éPàÌİÙadíN0<
€>N1N*Lä‹)<Tˆç*º’½)***""\r" R"***(:>3Š‡îYV$R*>”õ$k7LÉ’94àÄt5$Šz’FMC‰›dñÌqÍH$n¢«†!AÇëG™íY¸™=Ëaô©‘Î)***""\r" R"***(SŠO—¥J­·­K…Œe±9c×4o¹¨ÚLôüé„“Öš‚ œÉÇ)***""\r" R"***(Iæ¿­CE_"%«yJBŠp`zSåD2`ÅzPXõÔIi’äúš2}MBÍ´ã,*ÔqÔ›'ÔÒd¦£§ÈÎi¨´&¬:¤^ƒéQŠ	'¯j¾VCD€‘ĞÓŒ‡°¨hbzšÑD›“o>‚1ª¿™íG™íWÊƒ#ôo>‚ “ŒRÕ(6óè(Ş}CN½Zo>‚çĞSh«IƒĞz’FM-GE>R¬”9ğN2*¸$r)èç?…>A†b8ê„IÇ"UÑ&Iêh¨Û¡Ç¥3{zÖªÃ”ŸŸZB@5öõ£{zÓP±<¤¥ÇaHXš‹­9:ş\¶B²‡zU¿¥6Š¨Ä—aşo¹£Í÷4Ê+E£üßsI¿ßó¦Ó’pj”5ĞI{~´¢V¨”í9Å/™íZ(
Ö&óı©ÛÏ ¨HÈÅ¢‰)***""\r" R"***(X›yôy‡Ò¢GCHy95¢Dµro0ƒõ£Ìj‰>õ>´Q(ğÀğ)ÁŠô¨©U¶ö£•‹—RBÄÒS|ÏjF;qV¢Á«
ÎAÅ9YˆÎj:+E‰xêiC3“Q/İµJr– Ï¥*°j ãÓ#¥R€¬ÉšC×Ú£2·cM$´U( QcÖSœ~ÿ Z†”ÑÊ¤¥ÇaJŒMEæ{Qæ{SI)***""\r" R"***(E"|ŸSI“ëQ+níOBNrjÒ•‡SÓ§ãL¢¨’J*:)¤$É)***""\r" R"***(.öö¨#¥8IÇ"ªÈV&†Œ“ÔÔ`‘Òæ{U%qr¢›æ{P_#ªJÄ¸\xb;Òï>‚¡"—{zÕ¤.FK¼ú
Mæ£ŞŞ´ooZ¥r™õ¤Ş}5	=ijÒ°š÷§$pMGERÜJ(œKÇ$Ñæûš€SƒàcvCä&O ÓÄÍŞ V dw©(Jä8¦L\‘€)µIò’Rî8ÅFi|ÏoÖ©	¡Õ"ôJˆ{~´¥Êt­bµ3qĞ’”1óõ¨–Fjrs“Z¨‘ÊÉT’2iÁˆ89î*‰q$sÈ§‘‘Qƒ‘š(!Ä“$t4¡Û$t§	8äU¤„àÉD¬&Ÿæ¿­CRQdO(ñ!<irŞµi”{3Ö“yôÚ)Ù	¡êÄœpb*5]Ç¯jr®ŞõIjKNäŠÀç´ÀÄt4+)Åh”Y%>µ	”¢œFiòFä»­>¦¢ • è3TrX‘z¥8Iµ©+Ucò.“°¦î$çùS·g 5ö-Øÿ Z%!iÊxoãHƒšŠÍÊæ.mŠ
z”19¬ÛV!²_3Ú¤AÅA'“Rä†³zÉØ’œ?‹qõ§+:ÔİÑ(8¥ŞŞµO©§¯İ©‘)***""\r" R"***(Ø•Y€È=©ë&& æœ‚*1r,‰H§‡ÉÆ*ºs“Sk7dfİÉ¨úÔ•]eç©©3“YHÍŞäªpy4»Àè)ŠN-d÷2œ‰Nİx§yÕ>´ä$ç&¥ìbÙ>ò8ş”œç9¨òsÔÒå½MA›l”9hY9Í1sZZÍ™È”9# Ó‘Î
…w€qR!Ö“hÉ“+f¤VİíQFr3RGŞ²mÉ²Bã°Í!aÙi(©0rXOéÒ˜ŸxSê^äËp¥GZJ*Hm.J‘\•MzOc)õ§î)***""\r" R"***(GNNŸfö2h‘d#¯çOÇj*z}ÑYÙ2C··­=XÁ¨éCIÄÉÜ™eÇµ<ÉíPÓÙ€â¥ÄÍÈpv'§€AP‡9§dúšS6Éƒã¨¥VÜqŠ‰Kddšu+6®J´ôö¨7šr19æ“3—‘`JGô}Üu¨éOW T3&Ñ7=…=8QP+“Î{ÔŠÄµ6f-“ÀÆ)áÛj¸féêÇö£”Í¶XRpjJ¬²â¥W'¡5-¹X˜¿aM$´…À 6zSÊfØä' f©Ïjœ»‰ïYH†Ñ2KŸË¥=_w¨T€riêÄr+'s98Ø™d óRoÿ f«¦yÉ§«ãƒøVr]Ì$L­iáÈóP«“ÈÍ=Ia“Y½v!’£¸§	=ªHéJYˆ¬š1‘2Éjx“•X1éÊùïŠ\¤2ÂËø§™9Î?Z¬ÿ ?'ÔÔ8™²u“¶qNsÉ¨qR+gƒPâg'dN² sùÓÖOåÒ¡F-:²•“1{“‚CR+nöªÈÄœT±³sÍe$ŒÚ±f9üéÅÉéPä†—qõ¬š2™(r:ŒÓÒCŒÔ*I4ä'8ÍfÑ‹dÂcŞ$ÉÎ*Ulu¬š1h´’àJ’ÈªÈTÑ³sÍfâfÑ9š18ÍEæø¥ó¡©å1‘8r)D¤t “'4âI¤àbÉ·ƒÉ4å“ŸZ¯½©Q‰8¨å2“,	=ªO0ãıjbİiêøëK—C¦J­iáÏqUüÂ>í*È{šS	)<æ§yàõªá\ş´£qç5”‘adqR$¤{Š¬¬Â	ÇZ‡-,Ş”ÿ 8TG+Ôš¸íšTa(“‡nôå~x85[ÌnôåsÔ‰DÍ«—nÌ)é&zUEf#$Ô‘ÊG\ô¬œLd¬[‘OYTò)***""\r" R"***(UI9ÉéRô5›‰Œ’e¡+ŠU”äTÉèM(r+7bÕËjäŒŠp~ÇóªË)Ç)***""\r" R"***(OIsÁ¨q2p,‡8àñJÖ ó1ÀÍ(—'üjL\KK Àúv§¤¤öéU•É‘_=)***""\r" R"***(fâg%ro3Ûõ È ÉKè*i‘¡DÏ”ŸÎZÃ±ªáy4¥ıh¢Ä›Ííº•&aŞ«†ÁÉ§+äñV ™›,yÍN– VÇ\Òù€tÍR‚$›{zĞô" iˆèi>Ğİ³UÈC±g·ëJ% uªÂW4åbFsO–®N&'© ÌGz‡{RùƒĞÕ(‘ÊÉÃ°9”ÉÏJƒÌ÷4ìŸSZ(…‰KäcÚfO©£'ÔÕ¨‰¤HŠ_3Ú¢Éõ4dúš¥r“+n8Å<9yªèÇ8Ïj‘[sT ¤¢SëGœÇµD_Ò“'ÔÖŠ*Ã±/™íJ& `
‡'ÔÑ“êj”P¹Q7œÔyÍéPäúšPãÖŠ"q,‰›(°5 c´ıãĞÓå±6$31¤“Ò™¼zO0u¯•”˜94‚@:ˆÈç½&O©ªål9IüïÒ•eÏ½V.@É&1	¦©’Ò-o”ï4c ş•Uf'‚ß­;ÌÀ?5R¦Ñ-"f‘šše`qP´ØèZi›=jÔfOç5!¢ ó}Í/›×5¤b&‰¼Ïjp=ê¿Í8L¸ûÇóªåb²'Àõ§cUüßsG›îkU¢Z'2“ÔQæÈ —Í(›'ªP)8•‰Å;{ûTCœÒù¾æ©D\½É·¿sJ÷¨<ßsO×ôªåĞM$L$,84TjÙéš\ŸSN(‘æM¼øRyÍLç$š+eb’Cüæ§b3šŠ”;ÓpNÍ(v9¨ƒu¥Éõ4ÕÉ%ó=¿ZäãÍãĞÑæz« % ED$ÉÆM)rrjù@“­›îiVRNëO•ÊÉƒôõ—=óP	=E88^„Rå™7™íG™íQ,¥»Rï>‚š‹! |œúÓÕ¶Œb«ùŒÇ­=X‘œÖ‘ˆZÄŞgµgµE“êhÉõ5V`L²âœf\„84©E‡ùÔyÔÍãĞÑ¼z|¡ÊIæœcgµF[w¯ıïÖ­D\¨•[qÆ)Áˆà…w¦“êj¬ÉkRQ+Š<Ïj‹'ÔÑ“êj¬+"_3ÃJ&5G&–©GAY	23ŒÒ ’j,ŸZ\ŸSV‘-zS·°ç5\1 b?úõvD8“yÍG˜,j-çĞP÷\¤r2Q&@Í*ÌIÆ*-ãĞĞ'€jÔEÈMæ?÷¨.ç«Ty>¦ŒŸST¢>TJ²â²çßŞ«‡"•d#¯éT‘‰d8ïJãƒUÖA×wëOÄÕ¨ÜÍÄ›{zÓÖRG-UÃ3“N ç5\„òêXqÒ3Ú ûš_?Úš‹&PdâR;Süä÷ªÛÏ  ÌAÁj!À³ç'j]ãĞÕQ8Ï"çïÎ©BÂä'2(Å ”€*û9¥üj”U„âXY;S¼Ïj®$#ƒKæûŸÎ‹2KN1ŸÂ“·ëQ	7£qõ«I±Y"e;†qKP‰ş”àÄŒäÖŠ#%ÜÃ½*¹Ï&¢Éõ4#½\bDáˆzÊ{šdÿ &OzÑD—òGvâ…b¼SŠp)»Ò¾¦ZŸêËÇ	;Ò‡nãó¦¢ƒúSö7¥fÉl7ZUÉ<“ùĞÖœè*ŒÜ…FjPüi‹}éÅx¨•ŒÜ…Ş=)***""\r" R"***(9[#‚iªÈ§VmØåaÜdÔªwš‰pİêE`ÖnLÍ¶ÇQóšföìiËĞgÒ¦ì†Ñ($ƒNóœZmy¤ìe'bAÁÍ8JÂ¢Äiõ›±““%Y‰Ç4ñ!' š>ğ§‡À<Ö/s94K¼Ó‘‰ÍD®sór¿÷MC3l™	9É§SPÔĞÎsòš“&ĞğÇÖœ¤‘š	#“š‘>è©‘”˜äëÏ¥H€L@sØ§GJÉ£&ÉÔ 8§§ š2Häö©EdÓFrETjÌ°})***""\r" R"***(*±Ï&’Š±›ØqJMÇÖ’•@'šOB9ÎMH„óÍ4(8);4fØıÇÖ—ÌaÒ˜»¿Š– ÍØ‘ğXÔ‰‰>è© úT=Ì'&…Éõ4àãæ›E#6Û%Ü}iKŒqšmìÍ»ŠŠ‘dÏzŠ•>ğ£•‘tL$
3J$,8¨éS¯áSk‘+®IäŸÎœ2:T`r)***""\r" R"***(9	9É¨±‹Ü”Hâ²ãùTÿ 
’>™÷¢ÈÍîJ¤¯J‘àƒ{SÕÛ†¬f÷%Ş}<3c­@Š;c­-Le¹"°ş"jeprWñªÈIÎMN¤ G­+È›x<sJ	)***""\r" R"***(GN{ÔÉ#6îH¬IÅ<1¡3Á§noZÍÄÉ¶JŒIÁ©ã‚*sšvöõ¬œt!»“	 éšxw•WBNriá°0+"/˜GNYØƒ{zÓ’95D7bapOzx¸8ÅW§§İ.&l˜¹aÅ*·©¨ƒ‘O#5‘Ä¡ˆÿ ëÔ›­ERVrºzî9çğÌsQt§+pk6e(²d—)***""\r" R"***(?Í÷5 àäRïoZ‰#'bÂËïÛµJ’ã½VúTˆÀu5*Æl°&cĞÓ„¤õ&¡]Ø8åİüU&2±0›©ÂlzÔôû¢³q1’E•›#µ(bjº±^;zTŠç³qFMX±€Œ•$+Şª©#zÔêIëYÊÎ[“=sH$ÈÆi…›Ö“¡ÍfãcIæ•=M(œ‘×õ¨‰ÉÉ¢Tc$N³üÓÖQ×ùUPHéOG9©q1h²³•§ù¾æ««gµ=_ûÆ§•I2_7¶M/™†ÆjüğiCRâdË.G\S„Äüê¸b;ÓÈÎ*yL¤‹_sNYÏLÕpäSÁÈÍC‰‹E&zøÓ¼×õ¨—¨úÓér$g!şfFrjH¥ÏSPŒdf>^•R,$‡ëJ‡CP£tçšvöõ¬œZîN’‘Ğşu$s1ïU•³Á§£êj4dâ‹K1Ç)***""\r" R"***(Nó[=j¶öõ§,ºVnŒÚE•õ¦Ir2j˜•€ÅJ“+7)$Yó½¨Y2x& WÏ$ñN)***""\r" R"***(“€j$¬ËQËÇSR$™êj¬rÔÔªİÁ¬œŒe©9uÃ/ùÂäÒ@À¦¢g ÿ 7ÜĞ&Ç­2‘³–©E/ŸíBÊsÁëÚ¡%ÇZMíëZ¨#6µ,ù¯ëKç9ı*º9íO2qÀªP%¦Hd$ñúÑæ5E½½hŞŞµjå'Á§‰xêj°sÜS–e£•’àÉüßs@Ÿâüê(<N”Ô	qdèzäÓŒØ8¨C‘×šRÀZ(“ÊKçûQçûT[×ÖëëT DË.iÛÇ¡¨ÿ 4»ÛÖ­D–µ%2ã§ëGšşµöõ£{zÕ("a)îMo¹¨•ÿ ¼iw¯­iÈ;"O7ÜÒ‰°1Š‹zúÑ½}j”È”Mß;ÌZ„´¡Øw­=„y¾æ•e÷üê3Ú”zSP"Í'¿åM2c¹¦³±ééÒ›ó“Ójl“Í÷4á/GãQPHš¥ ³dóš7CQ3Œ|¦“{zÕ¨ˆœCJ]±P¬¸ö§™0:U(’ÒC‹w&˜X“Á4Ö“¿·Zg›ş×éV£rI•$Ó†;TÉç4å—
qíZrÓ%¢£óÚı)w±ïMCRI0ïùÓê-ËëNŞŞµj >¡¦ooZ7·­R@HŠ7Z{zÑ½½j”DÕÉ°y4ğ})***""\r" R"***(A½½ièäçSåĞM"usƒÎ1G™şÑ¨Õ·v¥£”•aşo¹¥óÔş5j L$súQæ-D€h{Õ(Ü	Ôœ{S÷CP	xëúR‚íıkEyY.ñéIæJJF$Šµ;!şcQæy¨··­(r#5\dK¼z€zÔ;Û=iU‰<š-b’'WÎiùv5 $t4äàŸÎQ´K’:2İš¢3Æ9©ò²lÉÃŒ`õ§+62)***""\r" R"***(WYI#'ğ§¬¸P3j¥YooZO8ûÔ~oû_¥4¹=*¬ÂÈ—Í÷4íÇÖ¡]ßÅRÖŠ#'ÔÑ“êi(§Ê‡ ŒÓ¼ßsL¢­D–®É„œir}MD	)w·­Rˆ¹Y v»Ï ¨ÁsÒŞVŠ9	<Æ(ó_Ö£ıå¼¦ ƒ””J{“@“=ÍF3iÛXö«Q‘ b)ë)ç­F3iU¶ö«Q#–ä…˜´›©¦ùÔyÕj$ò1á˜w§,¤‡{zÑ½½jÔAÄ±æÓy„ôÅ@®sór¸ÏÊj¹IäDÛÏ  ?¨¨Õÿ ¼iÀƒĞÓŒIqCÃŒô§«¨Ê¡§+ 95j"qD¢Lt&%\u¨7¯­( ò*ÔHqDûÇ¡¦†aQ†aŞ”1=õ£•’âL²ûşt 'ŸÒ˜N9¢©+µmÇ—Z<ÁÛ4Õê>´â œ‘T•ÉåB¬‡¨4õ“‚Zˆ®9QÍ °?5>R\IÃŸ\Ò‰=EB	ƒOBNrj¹	å%Y20)w7­1M.õõ«QMÏ ş´õ-MF$£~”¡Éäµ.FI¹z2}M1\c“Í;­Z‹F=Xc­H7 ©U¶ö­Iä?&;
)›ÛÖíë_BÛGú•ÎH1N	À5ö”>N1Pİ‰u0ÇqN:c$t¥ƒÆ+6fæOæÿ µúR‰Aè*ïxl
ÍìC™/™íG™íQooZ7·­A<ìeÀäÒù„ò?•B¤•É§ÂàT5byÉCrÇò§¬œqÍWŞ}=XÁ©l—+–RPzóOgäÕdvæœ\çŠÉ»JLœH Ğd#«T!ÏCK¸ŒÔ™¹4L%Ï­9dÅA@$t¥dÌ¥"È”1R#/<ÕDvÏ^Õ0îŸÒ¢HÉËRÈ“'ƒÓ­8H&¡VÚ)***""\r" R"***(Ø÷ı+39H°&â²ç­UGÀÉ<Ô‘ÈI†e)ÖLŒí§o_Z­æzŠp9¬İÈsE•œ/©c”c“TÃñÒ¤V<’zT;™Êe¯7=èóÚı*çµÛÖ³ºFLŸÍç©ÂCÜUts;úÓË„Òz‰²UbÇ¥VÁàÔAıE*9'RÓf“,+gµ<9E@$¡Å8HOCJÚJl¹=8¥Wãæ5öõ ;g­IW'W$|§ŠzÊqÉı*íéFöõ¥k™I¶Mç59eÍWŞŞ´#¯4Y¶Ë‚QÜÒ‡cŠƒ{zÓèqLÍ²U“4ààƒP)***""\r" R"***(?zúÔ´I2É‘¾ô«&Z€0' Ó”í9¬Ú±2jÅ(<
rËj®sÅ=	9É¥cËÁëÅ8J Ô°1Šr’FI¥c92a('ŠzKĞ~•\zSÓ€¨hÉÉùÔå‘€j¾óşE<:ã“K–æR,,€w©–C¹ªaÏ­K¹A¡ÂÆ2Ôµæÿ µúP&õ?¥A½½hŞŞµ)***""\r" R"***(–<ì‚)ÂrFEUŞqJ$ìßCFl´³y§‰³Ş©ùyZrÜÖ³qV3i¢âÏ´iŞy#¥SîëúŠzHGş•Œ¢K-	‰êiË>8WÍÏñ~”»Øw¬ÜHjå±)<Í<JÃŠ¨’ôü)âR©q¹Å‘!<ƒR,¥†sUb\Ôf~íC¦e"Ø—Ÿ½Ry¿í~•PHIëúSüßö¿J‡s&İËoSúS–^àU_7ı¯Òœ’t?­g(¹hO“È§,€œUD¹8œ%ÁÈ›‰œÒ.G.7S„¼ıê¨’‘ĞÔ¨àMfâs¶[Y°:Òı£5XIœ÷£{zÔXÅÜ¸&æ”OØUU“·J]ì)***""\r" R"***('dËxÆ)***""\r" R"***(*ÜsUR^Şİ)á¬ÜÛ¹q'ÈëSGr+=\Š‘eÏ Ön4_3zA1ïU|áœĞ&ª39"ß›â¥öª¢sœJ%ÉÀj—4Yó@<ÓÕ³Êš©½½ië6T8™H¶²cÚ—Íÿ kôª‹9§ù¿í~•<¦,y¿í~”y¼guWóÚı)D„ô4ù43{Ò`$S…ÀU5ƒÉ©C‚2MK‹¹kÎSOñÖ©ƒÜS–FZ‡C/,á‡5 ˜ç‘TD„v§‰2rµ.&REÁ:ç¥9n<Õ?8´¾oû_¥C„“.‰À9á>îõI%ô?8HIàş•2‘ugÇzx”¦©‰xûß¥=eÇµC‚2eåŸ4ºqU¢¸íø‡'bÚÈ@äÔ‰8èjŸœŞ”õ”jÍÀÊH¹çíx§¬ø<ÍRóÚ¥x5†-j_YÁê*d›ÓšÎIÈ&¥I½j%LÉÄ¼fls»ôªFãÒ“í>õÌÍÀ¸.2i|öôªBà“Kçµih,‹fà)***""\r" R"***('œµPÏØÒ	ÀéZ*d4]ûO½/Ú8â©}§Şœ&$sT©ŠÅ¯´ûÑöŸz«æÿ µúQæÿ µúU¨”´.2qOâ©‰TñOàuı)ò	«DËR	—HHOFı)êsÑW³L–\[ŒĞfoJ¬´‚84Õ;´™cíu \p*¯œ3Á¥¨9«P%¦\I±É4¿i÷ªnáÉâëëZ*aÊËi÷£í>õSzúÒù¿í~•J£å-ı§ŠO´ûÕun>cúRï_ZÓÙ¢v,	ÉéJ%=ÍWÑ¿J<ßö¿Jµ±1ÇyÍU<ßö¿JQ.O­_ ¬‹BsEH·š¨pÿ ëSüÀı*”IjÅ“.9È¤ûJÕrãnöõªöd–¾Ò;ŠCpÁTËƒ‚Ôyßí~”Õ4>[¢Ïœ´yËUŒ€õoÒ“zúÖÌR×¾”¦`FIªÂBz7œUF˜œI@OKƒœT[ÛÖíëZrX9Fa”yÀpj¸r:óN)***""\r" R"***(‘i¨âËÔŒæ”JSU·/­/›âı)òâZYÀ4ÿ 9jöõ§Õr	¢Ïœèó–«t¥ŞŞµ\¡Ê‹rw£ÎNõ_{zÒ‡#¯4ùBÀrÈ£½VY æ²)ïT K‰dJGAGœÕ_rôn_Z®BKsQç5V/é@vÍR‚*-yÙïŠÃ¹¨¶({ÓQ°$ZYqÈ ”ÕPKÖœµj,¥ËF^~õ#K‘×ô¨w·­#9Ç5|¡ÈJ]‡zÃÕrç<Q¹½iò‚cÎZQpO«‚ßÄiCÎj”
I<æ£Î8çŞ óÚı)D„ô9§Ê;"7ı¯Ò”HOCP=Å9dãƒŠ9I³%ÀóÍ8KŒÔ>a=ƒ!M5É±?›ş×éNqÒª‰‡sNûF*”¢Yõ'œÕOÎoJ_7ı¯Ò­Bàâ[óš—Íÿ kôª~n‹ô¥ŞŞµ\ˆ\¨·æÿ µúQæÿ µúUUrNüiÕJ(,‹oû_¥/œµX:RïoZ´Y~ĞOJ>ÓïP‚CEiÊ…ÊL.	8å—'“øUzUf~•J³-,€súRùÃ×ôªêíJ]íëO•‹”²% §#ÜÕe ´ğäuæ©"ZDÎã?…0ÉÎ:Tm'·j`“•ªV$Ÿ{zÒ‰Ô[ÛÖíëWdŞfO4	 èjíëFöõ§Ê…Ê‹+"µ(UĞ“œš|}ê¹IåDŞoû_¥\œı*:)ò¡r‡aÖ®Åxâ GøRùÅE4‰q'ŞŞ´o?{ô¨~Óï@”‚©DRÒN­Öœd'­UCK½½iòà™d94¾sUPÍM?#¦j”IpH°%=Í!“=[ô¨2G"—{zÖŠ(RÂÉÇ\Ó¼ö=ª®öõ¥BNrj¹EÈZdsKç-WGCFöõ«Q°¹K"Pyœ²`Â«,¸qJ%ç­R+•„¤v§	½OáŠ¬%ãü)|ßÒ´HRĞ”Ôõ—>õPIÔõ“=óWdCù?½³ĞQ½½©›òp:½§sı;rCƒóÎ)ÁÕNx¨è¨w3æ$/»ŒŠPH9’§<Tˆu=«'¹.CÕ‹u©LÀ.óè+6ÙŸ6£èÈõ¦o>‚œòi\.ÉC8Å80#’* N8oÊ¤c“PİÌÜÉ2=E89G¨¥Ü}MD‰ua\/qNŞ}*\’zõ©2rlKÏQNYx {Ô@¤İˆsdÆzšZbğÜÓ™±Ó“vf2 x©#sÏ
±c*HóÎi7s7fJ²p?:~ş9Ôq÷§Vos)1êI5$oŒTi÷E9>ğ¬Û1l˜0#9§8â¢§+à`Öm™¶ÉCd‘R#rÂ«o*’FMDŒ›,n´›Ç¡¨·ç4¡ıj,Œù™*¸Ïğù85`Aàäœ.d¥€ïùP%ÚzTy¢‚ÀRHÉ»’‰³R$ƒµVV-Ö¤ïøRhÊNÄŞo©¢U5)***""\r" R"***(6F|Å•`
Rş‚ F M8H{b—).D›Ï §+g­C¼ú
Rş‚„ˆr'ñŠ—Ì9æ«+©7ŸAG)‹“%Ş=)***""\r" R"***((pN*1½*±'T´ˆr&àŠxpzÔ àæ—yô¬ˆr'È"¤YoÖ«ƒN{Ô8¡n‹g88§ Î{Ò‡#Š‹3)"Àb8œ& c
ÈHãõ£yôY£7Y©éFşy“ŒÓ„¸©ØÉØ°àqNB)***""\r" R"***(B%ã¨¥WÏZ¹›E¿7ÜQæûŠ¯½½o¸©qv2,y¾â0õâ«ù¾â•esY´ÉjÈŸÍ÷o>‚¡VÉÅ9[jH{¤€—Í÷UX·Z‘X·ZÎQĞÊDÂB})ë/c¯z€1—ÌÅgÊIa$ç<TªÀŒçõªªçb²ñÚ£•I2}ÃÔ~tô—Ua =Jz¶G“D4[I€äô§™W±ªˆçb$=ÅfàŒ¤¬OæûŠrÉÏ5XÊŠpŸ5¦mØ´&AÍ;ÏöªaíŠzIüª\2lµ¼öéRÇ/Ò©Ç!Ï"¦VÚ~µ‹Œ‹k ?Z_7ÜT`Ç"“Í÷›…Œ['3`ô§-ÀÅVó	éŠ<ÂzbK£6Ë‚\ó‘NöÅSÇŞÇãOúŸÊ£†®] 
w›ISäuõ‘ˆ Ô8Õ‹bà‚æÓQdÅJ“qÚ¡ÄÅìN$ ç"Ê:UDÙ8Å9\çš‡"Ğ›4¾o¸ªáˆ9§ŠÍÇS±`04ñ*÷5X9y§+éSË©Œ•ËÕ†A¥ 0ªà‘Ş”9r™8¢ÈzS„˜U•¸äÒî'ß­O*l‰GBØ¸ cŠp—ÜU=æœ®OSô¡Á»u.ı )D¼õ[ ô4¾aïŠ‡ÄJ%±pJQ0'‘U‚•d'ŒÔû3Va÷F)Ë.xªhç¹üiáÈ=j=™Í$\Yá…=\„UA!#µ=dÏÎ³p2jÅÁ(nx¥ó}ÅVWÛÜS·â³q2h²³ÇzzMÎxª ç‘J®GZ—\n\ó}ÅBzb«‰	èä Ô8™8¤[WàdT‹ <š¬²qŠrÉz—'ÉÌŠ)<ßqQIıi¾jzÒQDrØŸÍ÷y£¾*5=hŞ§Ö­DOb7ÜQæûŠ_'‘ê*Ô.È'VÏ\S•±ĞÕpÄSÒN¸¦£©-2mçĞQæÖ¢ó}Å!|ÿ ëUÊ¬˜J€ÓÄ¹EVÈõ@àÕ¨‰Ä³æûŠxŸ§U_ÔSÄ£‘UÈˆhµö€Ü~t†AéPo\Ò™¸Æ*ÔåD¦R=)Ù8ÅBdcG˜ÕjÊXInqOó}ÅU°<Ó„Àöıiò•–<ßqG˜OLT
ù<â¸úÕªaÊÉÖ]£¥óıªŸSFO©«TÅÈXgÓñ J3É_'ÔĞµJÈYóSÖœAU.{
Uv'­Ii„â'õZ¨Ò‰HëøU¨k–¼şzPf`Šƒ'Ö¿·ëT .FMæ®zĞzâ«ïÉÇó§)?ŞüªÕ4&ó1OJ‡éJ€U( ²'ó€è¿¥)nÕóè)D¡z
¥‘>óè)<ÓĞâ¢óı©€œóO9I„¹èE<MŒUa"ƒœS„¹ô«Œ	³&óõ¥ƒÍ÷¢B:ş”ù(U§ëŠ„6G4Œå¸¡@‡IüßqG›î*±b:·ëFÿ ö¿Zµ.BĞ•qÉ£ÍOZ¬­ÏŞıiù¢š‚Bo5=iC©ïPd†”1j*Â²E€ÅzQæûŠ„ËÇzMçĞP¢O)?›î)wŸAP+drE(nÁªÔDà‹/E/›î*¸r?.óè*¹I±`J;‘øSüÜwXŒÔ™µJ$Xóı¨3dc›î(ó}ÅW")0pM88•_Í÷äu§È'bÄŒJoš=¿:<ÑíùÓ²V:œ„äÔ~`=ëJ­ºP·r\QFG¨¨èªQ@ì?#×õ¥Ü=j:ir*”‰²=E¡¨CúŠp'Ÿ írubİiN;T+'<ÊçûU(îIœsKæûŠˆÍ‘ŒSwŸAUÊ¾å…˜“Š_´
¬®IÅ:šŠê>TXf—Í÷uëÚUÉb^å„vıi|ßqUÃK¼ú
ÒÈDşo¸ IÏjƒyô¡†2MRˆDØÅµ@â”?¨«å°‰	Å<OÏ" qK¼ú
¥™“™3ÆE `r*:+ND$¾o¸ J;‘QQORo1OJPÀœ
„E9d ÿ 4ƒ”˜1^”ôvıj0ö Ò«“×šLVdşo¸£Í÷ÚdwaT£p³&ó}Å)***""\r" R"***( nâ¢g=iÛ3ÎjÔDĞê(Så¹d™¿­/›î**~ÁêjÔP¹y„ôÅ*ÈsÍ0.:KO”N$Â@zş”»Ç¡¨)r}Mh¢K6ñèiD£° Éõ4ªGvüê”¹Ï ¤ó}ÅE“ëFG¨«Q#%ó}Å(sÜT9¡£$t4ÔC‘–^;~4á'¯éP)ÈëNcŠ´„âË*ür)ÊøäsP,‡b”I´Ò%Äü¨.£½'™Î1M¢½^cı,r½}h¤ànÃê(ÁNM+²9Ç’1À§¤Š¿•BÍ¸c¨I8ÏjÍÚä9“‰Aè)Áƒt5
¶ŞÔåmÃ¥CDsêHÎµ4±&šÍ´ãÒí)***""\r" R"***(fÓ¹.dªÊ	¥Ş¾µ$õ4õè)4fæL¥O'¥8:µæéDÕ›V!Ï¹e[=©ã`ïUĞ“œšš¡¶ŒİBEtô§ïSÖ ¥O¼*[d9“nS€:Ó“¯áQƒšw™íP÷"é’’SNBrjmÇ¥'ˆ”‹(ê¡Æ9¨A `PKÌ\Ùee=£bª£cŒT¨NÍCHÉÈŸÌö§‘š„9‘šp9¨q!²N;ÔªÁ{Utq9©¶Ô4c'brp2i¥ÇaLi2}i7û~µ<¬ÅÈ•d äŠp˜‚ ó=¨“ŒTÚÄ½Kgµ(`x¨	­'?…·bĞ(:x”*¡uŠzËù¢×ĞÆReŸ3Ú3Ú«ùÔàAéEš2z“äSÖA´`T
àN)***""\r" R"***(•À<Tµ©-“yÔ¯_8©œ*mb,	ëRyÕQó*PpsAŞgû?­*8È?¥Eæ³J2éS"dX;ÒyÕ™íúÑæ{T™=ÉU·bœ­·µD3Ç¥;Ìö©oQ£Óš_3Ú 1“Iæ{R³%Ø´²ªŒS„€öª ÷œ²×ó©jæMÜ¶$„äæ Y2=}é|Ïj\¦E…qŒ8<ÕPÄŠzÉéÅ>TCE£2‘ŠaqØTBO4àÄt56fDÈã"¤W^§òªŞgµ9]ŠñÅC‰)***""\r" R"***(–Ær)ŞgµVsÍ=dçx¬ùL›e„p:TˆãµWÈ=éC‘×š‰DÍ–|Ïj<Ïj¯æ{R‡ê9@°’|İ*Pr3TÑ‡ŞŠ•dùsŠ‡'É*Hß•T>{TŠãÔrÙi$)ÅıVWÛNŞ	À¨kS	îK’zÒ† ÔD€2hWâ‹#¡edàqNY@<Š®;ÒÔ8™½K"PjA(=ëTÃ‘ÖŸ uâ¡ÄÊH¾“)ÈJ®% ¤3ÔTr\ÅÜ³æ{S–eUQ(=Îx­'ì\óä
Ÿ…@™Ú3OE#“Y8ËN4rJª®1ƒOVÛY¸³6[£vÎIâ¡ó=©LOzÏÌ²$d
zJ1ŒU5˜îëNYFìœÒp2•ÑqfÁäp”‚ªyªzS–Rx¨p0–¥Å›>9—â©$Œ¼TgµKŒerà”‚3Úª	ˆâœ²dzûÒ³fnåŸ3Úœ³ 1Š«æ{Qæ{TòÒeÁ =©w¯­Sæ$ã8¥Êfâ‹É(E)”éTã™¹ÍI½»Ô8£FÅ2”å’*©“¶)é'AúT´e$YĞSÒ^pEUó=©Ë.x©åF3‰me äŠp”‚ª‡­9e9¨qFĞ½ËŠx”ƒõª"Bz59d*1YÊ3jåå”È§	ŒÕ4˜ã§‰â³p ¶&UâŸ½}jªÉÇJpqßŠŸfdÕËk.ÑÅ<L¹ÅSx ÓÖoïT¸X‡Z/‘ŒSj3Ú‘ëB‰)***""\r" R"***(R†ÀéúÔTŒvŒâ«•ŸÌö 8î*¿™íJ­¸ãJ$ò¢ÒÉïš_3Ú«=ù¥2g“WÈÉjÅ3Ú3Ú ^)w(äš7dŞgµ9eP1ŠƒÍQÀ›÷çŠÑ@—~¥Ÿ9iÁÓÕAâ¿Ûõ­;’Ò-ùËJdœUA6zš™íWìĞr¢9Oj_3Ú«‡Å.õõ§ìûX“ŒRÕq2Š_9kE)***""\r" R"***(Ì°Š_3Ú«‰3Î(ó=ª•;ƒL´³c­/œµY%¨¥ó–­CÈÍ–D ôyÕ\JÈyÕJ Xó=¨c·ëP‘œRÕ¨Ø†‘dL¼
zºÍUŒS#¥_ ‹&eäb™æ{Teı)¬Ç5j|­“yÔå“ŸéUD¤t­8JÄâ¯‘ÈZó=¨ó=ª¶öõ£{zÓöh\¨³æ{P\væ«ooZPçœşJDæP£ÎZƒxô¥Ş=)***""\r" R"***(W)Vdâ@y”:Ô äf¿tUr"ZdË´õ§©\tÏ¥W”ğãš9	³,o_ZF“ÿ ×P‚GJF|÷æ©D,É<ÀO&€ÀœPOZPÄVŠ$¸–CàcyÕ `xïNS´ç(L²…9"% ªşg·ëJ­»µ"qêOæ`p(ó=ª)ò”›Ìö IÏ¥D­´c¾gµ5å' 0iD€Õ3Ú”HCV¢ÄÑlI‘()***""\r" R"***(@qÉ HFı+XÄ‹4Y¢¡ó=¨ó=ª¹J&¥A¨CäãàÄRq_3Ú•[qÆ*/3Ú•e äŠP&)***""\r" R"***(·µ=dU¨ ô¡Æ9¦‘-29hó—Ò ó=¨ó=ª¹C”°$)§œõ¨„˜=1CI‘×5j(9IiÁğ1Š¯æ{SÈÍW(ì‘8“×ŠBã°¨ÃƒÖ—zúÕ(¡şgµÇqLŞ¾´gµZ‚'”™\g"œw_Ìöıhó=¨ä‹-+€x§yÕU%=1Ú¼U(ŠÚ–7ŒRyÕL?„Ó¤õ­h£t>[–<Ïj¢¡V'‘NØşuj(—N²)***""\r" R"***(¼
_3Ú¢YŞ/™íNÈ›2q2Š_3Ú«ï”¢b{âš‚Ìµç-rÔò1Š@ÄUr’Ë>gµ`î* ù8Å8Õ	Fä¾gµgµGæ{R‡éÙ²¹IRN¼SÕ·v¨EZQ(=5å'¤/ƒŒTjwâ‚ø8ÅZ…ÄâL’|½*A2ã¥T`ô§‰23Ö¯†‹rÑç-Aæ{Qæ{U(ÊXó=©şrÕ@àõ©wCT …fMç-rÔ;Ç¡ 8' U(¢\I„ÀœKæ{T àäQÖšJãPL˜H3ƒN† S´ç¾g·ëZY©“dúÒ àšzúÒyÕI)2Ê bœ$µW3È§î)***""\r" R"***(Uš,È£$t5“”«&¥R‰›DâB?ıu'™íUÄœt ÉqUÊM®~XĞ89¦'½&O©®ËŸèó‘7˜=)***""\r" R"***(ƒp?Zˆ1$šppN)6Èr°à@<ŒÒî,p´Ú2Aâ¥™¹Q·©àÜ|§­FI=M*°ÍKwFnCè¦ï†•Ny¨nÄóV coQÒ›HX
—by‰AÈÍéQ‚qÔÓÁã¡©v!Ì™[nx§ÔHëOf¬¤e)ÓÃqPƒ¤çØÓò})***""\r" R"***(I›™*ıìš~G­@¤–5"}ïÂ“±.d©Œñ”àpsQä†œ„œäÔ=ÜÙ(`İ)j0H8ŒŸSQddå©%9\c¡Éõ4õû´˜™B´íÃÖ¡@Å<ŒÔ´ˆrDÈ@ÎMJ=VŒ“œÔáŠô¨hÆS¸şi¬Ã¤,M%+#&Àc9"Œ¡²2Š†…t=rh	ÀÊ2GCBĞÍÈ˜>:ÓÑÀ¨“œš’>ôI’o†œ­EGNV `ĞI ~>n´àr2*ãĞÓƒ8&¥Ä‰$É(¦‡ sšpäf•™‘*°\æ¼Œe&O¡¨h–ÉG4ğAïP9ç4ÿ 0{Ôµr2M.ñèj“súÓ·CRâÈh—Ì¦iwg½DK’:Vw%¤L„¦Q#šz°œÓå'bT?--1qK¼zÏTÌÉÀ R‡¡,sÁ4ªÃ¡?;"Z%·Ö¤·Ö §†)***""\r" R"***(Ò†®bKJj0Ny'ó§¡¨2dÁ8§«`Ô@àäÓƒŞ¡êCØ“xô¤Ş=)***""\r" R"***(0:Òo†¦ÈÊäë'¾~”æ’j })***""\r" R"***(99ÎM'$É²CJ¬ Á$w§õ&dë*‚iÁç5[x÷§+œdT8’Ò,î)***""\r" R"***(IŠ5XKZx‘p*HnÅ¤‘zOŞ*¢¹=	©2}MK‚1lœ0nôªpsP£ y=êBà3Pãs&L2)***""\r" R"***(8È£­VE/˜IùªyY“v,	ò)Ù¥WI½8J;QËs7-IÕ±Ö—Ì† ó}Í=c­KD=IQ×wz•Xg5_>•$rv&¥£)"Ò¸Ú)âTÀª¾gÖ•eç¯çY4AhH¦¤2)èj¢É‘×9Xõ¤5bÎñèhŞ=)***""\r" R"***(Aæ´hó}ÍO³FDû×ĞÓƒƒ€M@²Sƒ¹£†L¯¥J²©­¼‡ò¥Y<Æ¡ÁI]ÒPzçò§¤«ÜÕU—ßò¥O š‡É;ÄŠzRïZª²0iË)Ï&¡ÀÌ´² Í8¸Æj°Í(|ğ	¨q¹HŸÍOZPÀÔààQfdN­¶¥óô5U$=¿Zw˜sÈ©ä3–›–D™ùG­81J®’gŞı£øš—NÆ2,ÈÆx¡eÁ5¿¯4àÀœ
—)nYYu4õunAª¡ÊñŸÎœŒMfàÌeREÍêÇ Õe™ºÎ”9ìsøÔr¸´ZW súSÒEÆ3Òª¬µ"ÈzN(Í¦‹jãhÏ4¢@:UQ#Á§	3Ş—))***""\r" R"***(Ä©Í8>8ª‡Jxb:šBE¼QB¾;Ô>¦¹^sG ¹K~pşñüé<Õnı*¯™“×åq´{2ÄîêF)D©µz“FñèjãL‚1OJ]ÃÖ««g¥HŒOZ¥1ÅÏcJi…€8"ãĞÕ¨HA©^HªûÇ¡£ÌúÕ¨	«–7JP‡=sùÒï•j–™d8>ßZZ®’ß­;Ínæ­S6G¨¥VAÎjãĞÑ¼zµL	Äªz_0zUq Ïz<ÏöR…‚ÅãĞĞ%ÛÀªşo¹¥cÖ´PAbÊÊŞ¥óôªë&G?¥(“µJ™.%€À÷üéw r)***""\r" R"***(@²S·Š~ÌBÂ°#“FáëUüÁıêQ'¡ÍÌ\¥ àsJ²z}j ÜgwëFüëT¡rylZ2¯­0Ê­@fÁÀ¤ó}Íj 4‹Ç¡£xô5_Í÷4y¾æ«•‡)cÍ÷4y¾æ«ù¾æœ%ã¨§Ê¨œIŸâ?*È£©ªÊùèM9	9É«Œ”±æ)éJ€;Ó„¢Ÿ(¬Ë
ã S²=EVà)Û‰ïM@IäzŠ7»¿Zƒ'ÔĞŠj³,+1ş/ÎŸPaNó}Í_!)***""\r" R"***(“šnõô¦Grh­À¦ Éh0=éj>ér}MW*"Ì‘Ó“J\v¢Éõ4"…ŠÍCšZ…d#¯éNOBj•1X’€2y¦dúšŞ«9Q8 (¨„˜çğ Içó¦¢M‰F3É§îµqÅ.ñèkHÀ‡©?š´y©ëPo†€À÷«ä™?˜§Šrºç?Ö« Ó’NsšJ˜Ò-o†ãĞÕ7ÜÒ¤€œäô§Ê=I¼Áèië'©ÍC½}éwÑ¿ZN(I÷C@ ŒŠ…dP94á(ìM
 •ÉiQù¾æãªQ‰&ñèiAÈÍE¼zPÇj”KP&óz­bú‡,üèÜŞÿ j ‚ÌŸxô4â¡RsÔõ§ÑÊ!ïÒ™FIêh«QV"[Š†œ¬ÍÔÓ)U‚õ§d"T$õ4ê[=3K“êi”•“N¨2}M=XíÕ$.BJ)™>¦ŒŸST¬.T>¤¨C€1NËxşuVBq'	Å-EæzPùş/ÖšDòR‚É¨·SFãêjùA+"}ãĞÑ¼z‡'ÔÑ“êi¤®ÛÇ¡¥Ig5O©£'ÔÕògÍQĞÑæ-WVÇÓô5J Ñ>ñèhÜ§½A“ëO_»Z(\TL² àÀÔ"ôJ|¡ÊL
ØúÓ²=E@‡zJj$Y2LQFAã5õ£ÌõJÊL§œ“NŞ=)***""\r" R"***(@?ÅúÒäúš9ZTM¼z7CPäúšMÇÔÕr±ìO¼zO0zN,Z]ãĞÕ$ÄÕÉ7CNYTPï†€àñV¢.RÀ`yÍ.G¨ªàœpiAõ&©DB|QN‡¶>µ `{şu e=ÿ :| ãcòÙ‚1M¦ooZ7°äšİ¶¡üÌ}*š‹ÍÉàÒ†;†O-‰ËBmëëFõÏZˆ¸íH\œR½ÌÜÑ=j)***""\r" R"***(ÍëNYö¡¤g)Ñ’:ÍÏñ~”““PìCd ’q¸Ó‚õ°Òƒ‘œÔ6Cd½)ëĞ}*0Ê ¥HÀ5›Ô‡"}ëëKQ†ñÍ)s*dfä<pEH<Š€39§‚G"¡¤CdÈ½4ì‘ĞÔqdã&\
ƒ7;BIäÓĞœš€8î)êÛ{T´ÌÜÑ0 ò)j$sÚ”’y&•ŒÜÉ;šr8Îjr°ĞĞ¹É©á”µ¹ÇÊx§«Æy¤g)# 2jHß?yª¾æéûŠŒŠ—c)2rÀFõõ¨¼Ïj@Í[ëRfä‰·¯­×Ö£Ş¾´o_Zs$Ş¾´o_ZzúĞ\”XdL„äÓÃwSU£vçšHCJQ"R¹)| >Nˆ¸cÖ”EAë÷jA…^MA2x§ï_Z“%#"¤Å@$ìqÉ Í»–¡ °Ô+'sCKƒ×)***""\r" R"***(XMØ›zúÑ½}j/£~”	I8)***""\r" R"***(úRÑadÔıëëUC23JO=IoRÔn¹Î{SÃ2)***""\r" R"***(TWç
ië.;â§•™½Ë9ÁùZœ¬ äÕQ!=)***""\r" R"***(9[=MI›Ü³¼J<¨#NWéÏ5-äX^ij%”í4¢BO)***""\r" R"***(úRI±sØH#Šr2÷5eÇ&•_Ÿ”Óå3nåƒÆ•Nj/7ı¯Ò‘¥ÈÆsíYò™2Æõõ¥W]İj¨“ÒçµúRp¹œ´-;0)µÊ	Ájp`İ)***""\r" R"***(O!™2:š•J¯ñUA )***""\r" R"***(8L;œÑÈg-K[×ÖƒÎZ¬% ¥àuÅ´Ëÿ =YBšª%ÉÀoÒ”9úÔ:foBÖõõ§#¯MßJ¬²À4ğàµ7râå©.85E&#Œæ¥ƒĞT8™8“† äµ?ÌŞªÛ×Ö€àtj‡6š-+äƒ)Û×Öª¬™ëùÓ·¯­g$CZ7¯­Çf¨Q—9Í;zúÔY™µbÀ`FA¥àÕq ¥ŞİÍKW3jÅ¤“O5"¿¿5M$©V^ƒ?…'Û¹h8Ç&œ0zš¬²á@Î=©|ßö¿JË–®[ c5&õÎ3T–rx"ÈÚBe’@êhŞ¾µ“)jMàt5<¦REëëOF:Õu¿(p:5K‰”¶,o½=_=j°v<ƒNFô56V0’, ğjPÙû¦ªnoZrËïŠK™²Ú°“JOª‚BN~”øä#‚{ÔJ'<ËAˆèiU†95 —®)D¼}ïÒ¡Âæm´XY9À4ğëMUäõÍ;zúÔû6C‘j7^y§©ª¡È§ù¹ş*\¦RÔ°#ƒNW òj°”†4ÿ 7ı¯ÒSnZWR:Òï¡ª‚aÜÓ„€Ô8»–Õ•¾ñ§£Ud|´á!nCRä3–åÀAèh†«,¤uâ²+æ²•3"Â¶zõ§«`òj²¾9"Ëÿ …C´®»FM.õõªÊêFsNŞ¥À†‹A× f¥Ü§ŒÕ0ê{Óƒ‘K–Æ|¥¯0xÑæïTB-úR4£šj7%–7¯­×³UC.OZU˜çƒZªzÚ-ùƒûÆ0xÕo9¨æ«ÙØ’ÚÈ{œT‹'¾>•Q%¡Å=%àÓå%¢Îğzš7¯­W2ÔÑ½}i¨“fXŞ¾´n_Z€J¿J<ßFı+HÁ	Å“ùƒûÔ¢P;şu_Íÿ kô£Íÿ kô«öh\¥Å‘E^~õV½)”gƒT È²,y¿íQæï¯æÿ µúR«ää*Ô,…|wqNŞ¾µ°ûÂƒ/=JjÉ÷¯­( ÷ªşwû_¥(†­@¥­È£9£zúÕesÑ8HF­Ê‰Ä€t4¢\µ_Îÿ kô¥Îj¹¡h8Ç=hŞ¾µ]%ùG8¥Ñ¿J9ìYY28ÅH…OZ¬:
‘_û¦­A\–ÉX p)¥€êi/löéL.{VŠ(‹6M½}iC)8ÍA½½hŞŞ´ì>VXSúRşî««œüÆŒ3œÑ`å&Ş¾´ ‘ĞÔ[×Ö éT“).â;š<ÁıãQêhŞ¾µi!4J$çïSÖN98úU}ëëNWÀã¥R…É'SÃ.0MWzvæéò	¶ZŞ¹ÆiNz¨ôï´`àœSä%–7À4µ ”tëHeçü)¨‘"ÈlM;zúÕA)'¿J<ÜéOÙ¦IozúÑ½}j¨œ
_<·J¥Lvl³½qœÑ¼P	sG›ş×éT©“ÊXó÷(sÔ­æç€ß¥(vÏZ|‚jÅÀ˜Ò†_Z®cš_7ÅúU¨d[¸ö¥ª‹(4ñ/=j•2Z±bŠˆÌÄb›½»š¾@³'¥RšƒÌö£Ìö£|¬³½}hŞCUÖLJrHV¥Ê¶,¬€õ4»—®j )***""\r" R"***(oû_¥.Uqò¢}ëë@vjƒÍÿ kô¥3qM@-bÂ¿9İNÜ£©ªoû_¥(zÖŠHµ¼†—q=ÍWY@ÆMH%ãï~”ùHœ0=)***""\r" R"***(€8& ó}ÿ J<ßö¿J¥XŸzúÒ¬ƒ<µWóÚı)VPx&«–‹[×ÖëëUÄƒ³Rù¿í~”¹Ü.N€ij¸“Ã~”»›Ö©SKpsKUÕ›éK½½j¹ œ¬0j—®)D¼õı(äÅË…8ö¥óÚı(å&Ä•%A½z‘V¢¤ôÉ¨ŒÌF)»ÛÖ©@9K[×Ö€Êz«½½h0`	ëUÊ¥º*¿›ş×é@˜Éı)¨êO³eŠ	QŞ¡ƒĞQæ{VŠ!Éb]ëëJt)***""\r" R"***(P'§oZ¾Qò²Ò°ÀóOVpMUYqßğ§¬ .ªQd´XÜ¾µ uÀçµTöİúSÃ©jùY<¬±¹}iL‹T>g·ëK½}i¤„›×Ö€ÀœQ—_Zis×8ªQ¸Y“Òäúš­ç y?¥8H)***""\r" R"***(Z€r“äúšTÉêZ‰g9§o_Z|¬9t$ÀÆsúĞJ¯SQïŞ£zúÕ()&õõ£zúÔ{×ÖëëO”\„êË·­(`x Y àx`{Ñ`p%§+zµE¹‡z7·­4…È~[îcŞ’Š*›?Ğ¤*M?9-’åqû—Ö€Àô4Ê*LÛ†—¯Jjg‘NÁ=(¾†nB®Ü|ÔåÆ0´Êr&¥»’ä8c<šx*£¨ò=E(Çj†®K¥Îx4ñÈ¨éû—ÔTµbdÁˆèiõ
s“OŞŞµ3rD‹¤ÓÁd€35"ıîµ—"dû¢Ê;Ô{‡­( ô56hÆMCNBsQ¡ ò{S²=E#6ìLŒ¾´íëëQ!94ìZM\Îö½}iAİ÷y¨À$àz‚ NDŠ0 4d{şT'İnµ73æ$Râ¤,¤`€:|d“É¥kjCv%¤,SC
e	\Å»Ş¾´ ‚2*:TûÂªÈ›¢Š)‹˜t}éÕ$t4»ÛÖ“W%¾£‹ÔÒ‡Ààş•$õ§'İüi4¬O12HHëNWäÔ!€9R‡b:Ö|¦r&Ş¾´¢\éPooZ7·­±)***""\r" R"***(Ø°¯FsNŞ¾µ ëOÈõš3r$Ş¾´¨ÀÀñQdzŠPıƒTÙ˜œ0=)***""\r" R"***(-FĞ´»ÛÖ¦Ì‡-I€y§CPïoZUlõ4‰nå„ u4àAéPÇŞ†‹Ñ b:r°<ÍF­‘É£#×õ¡E2	ƒ0)***""\r" R"***(Îy¨ÃphŞŞ´8ØNÈ°’qN¤õ¨"¤Ü=jyQ›dÌÜği£ƒLŞŞ´o8¥k½‰·¯­×Ö¡V$ò~´úS7°ıëë@L¢TA2¶zšuB„äÔˆ@ÎM.RZ†œ	æ™‘ê)Üt£”ÎDÊÀ6	§†QÆjº¶iD‡ûßL¢e%r}ëëR\j®ö=èGSY¸™ò²Ğ`z¸Çª¬§4àÀK‹!¢päuõ§		èÕ
É´¹¿­CŠfrÜ°Œzçš_7ı¯Ò«†£Rï=A¨pFmu,«ƒÖœ$£Uu8µ.â:*ÍÀ†ËyÎhÀj¬’~ííšS'bÀvîié'b
®’:z°4¹Lš,‡Ú½x£Íÿ kô¨0ã4=ê}™Ÿ+,=ù©c—¶j²¹Ç"¡©p@Õ‹&O›Å; ğ)***""\r" R"***(V{ÓÕöğ+7™H°¤“NÜ1œÕa'=)âLZ—	nXF\õ§	 èj¯™şÕ*¾G5ÊZ—@y-K½}j¢¶ßâ©w“Ñ©rKbpGPiêÀŒ’*§˜OF»ÏsIÂæRØ/§‡R3š«™'ó©pj9,e"mëëJ²Æj ç½;põ¥ÊÈh³æöİK½½j¶HèiÛÎsŠ|„5bq Î)***""\r" R"***(80ÎAªÁòqŠz¹^”œ›E¨Øn?Zy*9Z¬’nêE;#ÔT8#)"pıH„s“UCwSR$‡¨©pFM\´¯ıãK¹Oz‰=XRäzŠÍÀ‚`ÄSÖ\¿…Wc¸§†g?­G"!–ô¢QĞœÔ˜p)***""\r" R"***(Ïz‡Z-_Zz¹OÒ©«ò~• ´½™“EƒpGšfàÔ>g·ëI½½j•2ynN%ÉÀoÒœ®AÉëëU–F4á+Š¸ÄN%Ÿ7ı¯Òœ²Ş«‡#¯4ªÛ1WÊC‰`HCR$£jª¶ŞÔààõâŸ#‹>oû_¥8H¤g5S#ûÔ¡ñÑ©û2YozúĞX¦ª‡nÍJdb*Ô	jåëëFõõª¾aÎ3O`}ê¾DKV,¡§ï_Zª²ç?J“Ì?ŞùPš&Ş¾´ ä‡Ì?Ş+FOJ$»X²²dzûÒï_Z€àÒù‡ûÂ«’`A<z3“U·±<5ÛÖ©Dve­ëëFõõ¨2CJŠÕDh˜2óÍ*¹Ç¢§,˜ã"R,É—îÓ€y5ÉÇQJMDI2ÂÉèsO†«uğäu«åD¥€êhŞ¾µÉü©›Îx5I
Å­ëëFõõª»ÛÖ•\“Œ~5\¢,ï_Z€ƒúU|ïPÅO”i2ÈúRïoZe#¦)D¬jÔfN®1ó]ëëPyŸí
_0ÿ z¯”’`ËœOV rj r½y¥TuÅ
,M\ŸzúÒù¸ş/Ò ó}Åaşğ«P&ÄşfxİN;1ÅVŞŞ´üQT¢KW$Š]íëQÜRïoZ¥&S‘É£zúÔ;ÛÖíëUÊ+o_Z€t5öõ¥VÏSV¢€°²+æ—zúÔ ƒĞÒ†#¡ªöh—mëëNW=Aâ«ïoZ7·­‚å,—' Å&öõ¨Cärijù<¤ÁÈëÍ<9jcéš9y§Ê…ÊLÒ…¿J@ê9Í2Š,‡dH%ÉÀoÒ—{zÔ[°x"”Éî*”
Jä›ÛÖ€äu˜¼)QóÕ…>D;X”8=x§=ª,QEO%™/R]ÍëN;·éUË@`ER‚bäl±½}iU>SÅ@$Ç Šr¶G$Ur É··­80#­Aœ÷Í.æèå°ùKQĞšœñQn´¾aşğ«IbMíëJ¯Øşu˜¼(ó÷¨²‘8a)***""\r" R"***(9\çæ5]Y‹`šu
*âåDâE¤µUBäö©Pœš¾På'GCHe#©ı)ˆèi	'­¦n‚_ÒHÎEAE;"KJË·­.åõªêF94£¡£nXöİOÜ¹Æjº‘ÈéJ¡¢Ö!9a)***""\r" R"***(7{zş•sÚíëUÊÆ ‰7·­*–$Q9äÓ÷«Q)&åèÜ¾´ÊG$c|¨	D€t4¦Q*¾öõ¥VÏŞ5i!X›Íÿ kô£Íÿ kô¨·/¨¥È=)***""\r" R"***(W-ÇbQ!<ç"®Bà*€33NVã“W‡-É¼ÃëúSÖBGôªôõ#‘Ò¨RÄn}iÌç…WG^h.zçÔC”—Ì=…&öõ¨Ì™È¤ÈõqŠ(cM88)***""\r" R"***(@K¼W`å,¤ÿ Zx†«+`dÔålõ4XJ…ï]ëëPn7~´d†šErï_Z7¯­A;ÒdzŠ¥‹”³O uª¢eÇ\ş4¢Q)***""\r" R"***(>F¬¶ãƒFöõ¨€9§«c¡¥Éb\OËê)¥ı7'Ö°?¼œ¬?#ÔRÔtdúĞK›$Èõ£ ô5(;NOz\È†ÉcïOW¥B¥ûñR+ƒ÷MCfršœœš ÉÅ>¦ŒŸSSÌG:M; {S‘N^”_]¥6¢•Fî„QFHèhm‹“FAÎ)***""\r" R"***(:£É)***""\r" R"***()AY±sE?#ÔT˜÷¥RÄàµI.I“dd`Òƒ´äTk…9¥.OÊH“Ì'¦)ÊKu
u©Ò“3r'¢£IIéÏÖ—yô6lk¡ã“Ş¥VäÕubFiÁˆ9ÍC‰.I–0))ŠçoJ7ŸAG)‹&R1ÖŸz®$#¯éR£¥+2&9Ï'4ÜQM,OzJZ7rLZUûÕ89§+’q@‰²CEDÌTdP²18&›MäL ¦† )***""\r" R"***(FŠr±n´ˆs¸´gE5œƒŠM\–ÅÈõ"‘·­C¼ú
ŸJ\¤Ü›#ÔR‚;ŒŒÒ«©!²|ƒĞÑQä†”¹#Rµ÷2nÃ²=E9ÎsQR¡94˜µh°„dÓ²=E@‚)ÛÏ¥ID¹¢— ô¨U‰84ğÅzUYn.bÊÏ4¹¢ G<ñK¼ú
Vd“dzŠ\Æ¡{Óî)***""\r" R"***(>Q6Ñ(r)Êr3š„9¢Cÿ ê©"í–wQKP	)D§ø.FE™g#ÔQ‘ê*ÄsšÙ8Å.S6™>G¨§!ç¯ lğiÁˆ¤âÌÚhŸ#ÔQ‘ê*çĞQ¼ú
\ŒDÙ¢‡ÔÔ ƒĞÓƒß?Z—KdÙ¢ŒQQo=ÅÎxr²ÄÀÆµæ²+3) bœc­C¼ú
x9¨å!»FG<Óª¸$t4á+gš—&N§´ìQP³Ú‘d;¸¥ÈÈeŒQNCÎ	¨7ñÓšrHsøVn:™·bÀ%NE9[=qP¤‡8Ïj]çĞVnÒ‰1ßõ¨ƒ–dÑIÅ37æN†®r5´àäTrØÍ»”ŒrirCP+½)àœdRå3¹8#š|dsÍVØ¥Y9©äÕrz`d™±œÒ,§84¹L$™ae=Í=dÉê*±riD„u©pF2¹kpõ¥V#¡ª¾iìÆœ²0èzÔ¸XÂW,«g®*E|ç&ª¬„ôıişo¹©ä2’,ŒÓĞ’95Ueb84¢Fvö¤àd÷- ğEH²|½ªªÉiáÎ?Æ¡ÀÈ´œŠZª%#­H%b2)***""\r" R"***(O#&E¬Z2=jºHOZq“.S);)Óò=EUŞ}8JÀóIÄÈ² Òù¾â«	²qŠPäv¥Ê&ZIëR$‡¾*¬d§µHµ.73jåÅlt£Í÷XL@ÆMµO!“‰gÍ÷õnâª	Iœ³2ÒtÄÖ…ås´qFóè*°¸8âæ±ïPéíĞœÔæ¤WÅTó_Öœ“àÒtÑ-\´_Óõ¤Ş}Aæ·­(	4r¡6óè)É'5bZQ zĞ 'b}çĞR«œóÅWó[±£ÍZµn‹BB)***""\r" R"***(RU5Ÿ­J’œ*”Z&Z“äzŠ2CPï>”yŒ:U(ÜVNŠ]çĞT"l”'j”Iqd£$õÅ<`qšƒ'ÔÒ‡#µR‰-–T(èij°—	§ù¯ëOVM@$t5šİÍ/›îjã å,+:şTá‚y5Ye9àştï5ıj¹q³,€ ä5.G¨ª¾kúÒ¬Äu«Pi[)wŸAP#±ïNÉõ5~Ì	wœò)Êëœæ E.óè(åBjåÀŒç¡‡cU„¼u?…89Å5r²Ğ#šw™2*§šŞ´ÿ 1½)¨k“ÏSúÑ•õqèhŞ}W(ÔI²=E&à9ò¨·ŸAFóè)¨;…‰‡4+äóQï>‚çĞVŠ,!óNÈëš«æ0éNY	ÿ ëÕ¨Í3àğEC×ùTE‰¡[hÆ)¨Ü†Ë-?~G'ó5THsOY?Æ­E	¦‰ò=Eµóè(Y22ERˆ­rÖGLÑ‘ëPdç9§Õ(“ÊHúÒù¾â¢¢­@’_0ûQæj[­.óØSTî›Ï ¡_=H¨÷ŸAI¼úSö`YBriÙ¢«‡-Ğš\ŸST¢KLŸ#ÔQ‘ëP‡À÷£Ìj®@å&¥``Py¯ëG˜;Š®Q8–ƒzÖ¤Èõªa2)***""\r" R"***(JúÑÊ'Ç›î(2g¸¨¨'4r!YdÖŠ‡Ì ñA•ÏZ¥ÔI²=E€èß­C¼ú
U,zŠ|£²&}sOÜqË~µ_$t4¡È£SdÙ´¹¢¡Ş{ŠPAùZ+–Ä ŒğiC1QR‡"šB%W$Ô‰î?¯¼ú
Q)îMRŠ`YÈíEB²ÿ Ö©7ŸAUÊ€u*Ÿ›šfóè)7ŸAG(2Â»­?#ÔUQ#
U‘‰Á4¹H¶¥œQNFõoÖ«¡$òiáŠôªQVXÔQæûŠ…H=(f àUr´&‘.ìœƒùRäúš…NFir}håd4‰ÔŒriwï~µ ‘±JÔSå'‘“ï4ñœñP+œJQ+Š9Jå±k#ÖŒQU|×õ§+±ÍZˆrØŸ#ÔR«`ä‡yôõÔEb7ÜR)***""\r" R"***(ÔŠˆ¸9¤ó=ª¹GfMz*$—oQNîè*’wV>œ„É¨‹Ş“-ëWf¥ŒQFG¨¨“îÒÕ%aò’nŞıiDƒ¡¨€'¥8&Š©+‡)8“±#ğ¥/ ¨sh3Œpµj"å$¢¡ó”<×¥W(r’ÑøÓ2}M>¦­D9IPíçwëR/=Xşu]	'“Úş½>Qò“Ğ¨Ã–èMÒ@¢HXœŠ*:PäU¤„à‡ã9§ ¸ÎïÖ˜§#4µIÊH¡©#ãU|‘ĞÔ€‘ĞÓqŠgæR1ÀÈ¯3˜şårŠb‚[$~4ğ èåCfnV
r:´ÚTëøVmçqôèûÓhÉj’´Í´ãÒÄı)( Í¶Ç§İ(è*l¸üjU$¨&“‘Š(¥Ì+´=[wjZCÀ8İíëI»‰È}*}áQ†rx§ ùäÒ'™ÑQƒƒ‘J7 ÎR¸út}ê5R5"‚ÈíNÚ\Í²DïN¦Æ<Ràz
F|ÂÓÓîŠf è)é÷jZw$Oº)j:zôJ’… ‚¤¨éŞg·ëA›wE4¸ì(ó=¨#™O¼)ààäT>gµ(Ÿ—XNJÄ½i;ş>ƒó§GœóéA›jÄ±÷§TtwÅ'±BJ*:2GCR•Èl’Š'9Í.æ=è±<ÃéëĞ}* øÅ9X‘Ş¥¦Km’T•qßŠu.S2JTûÂ¢¥E NO{Tk/AŸÂ­¸ô¨q%¡É×ğ§Ó¶ö¥ó=©­	$½:¡ó=¨ó=¨%ÜšŠ‰NáœS•öŒcõ —¡2}ÑKQ«œdqK½½iY™/Aô¥<P‡ã¥8?ıTÃ˜’zĞ½GÖ›æ{Pdô’±›DÔw¨7µ804¹LŞÄ´TtQÊA(r:óOà5W§,„M'5¡)m§¥.ıã®E@\ö§!$dšTg+¢PH9õ$¨É¨w7­/™¢—)›W&”á'Š®$­;'¶)8Ë ‘Ó½ àæ¢Yqß¤’y¨å2jäÁòqŠu@¤ƒ€j@Ä}=)5b	“$ )j/3¾”yÍéPÓ¹”•Ù0r)Ûª¸`Ç­<9j9nCE„$ç&œI'$Ô 4¥Æx©åîfÑ`?­=ÎsU¥89KÉ¢Ò·pië&*¢ÈÄN;ñIÀ†‹‚N:P‹úÕ`íÁ¤IsÔRå!¦‰è'™íAsG-Ì›&¢ ŞÔ¾gµ.FfÙ>ãŒfŸûUU•ö§«sê)8ó,ùÔğäpj¨”9eÈõ¥ÈdÕË`ƒÈ§+ö5PLGõ¿K›E {ƒNIëùÕPäŒ†§‰IcSÈe-‹^fGLş4å“ÕT;qƒOIr:T¸ÉÕ³Oó=ªªIÇOÖœ\v™=ËgµgµWó=¨ó=¨äb,†ã<úSƒ‘U¤tô˜ö©ä%–ÒA)àƒÒ©ùíÓô˜ôÍO#3v-‡#¯4¾gµWY89¥óš—#fMjXV'‘OØşuXI‘Ò—Ìö¨äd²Ò·piÁÇz¨³Â®·ãIÓfm"Ğäf€HéUÃ¿µH²’9¨äd)CU÷·­ÛÖšƒ"Ì³æ{S–N€Âª‡Å9dÀ?…W³b”0ÃúÔgµ
ûš€¬‹R:
zËŸz­ÏzrzšµL–Xó=©é ÇÕn”àç¸«äB,äR—ªºœŒâ£‘'™í@pzñQùÔyÕJ²'BsJ\vÊZ™íZFå$ó=©CQÈÆ)UÈ‰qH°¥/™íP¤½éNó=¨å%¤J²p)ÁÈëÍB­¸ãàÄp)***""\r" R"***(RˆœU‰Ä„ôj]íëP£&–´²‰2¿1§"«ÒîoZ9upHéR) g=ª°˜÷5"KhäbjäâN9«.:œTBAiCƒÖšƒ&Ì”’zÑP—àQæcµh .YQQyÍéJ%'ŒóG Y’T‹Ğ}*)***""\r" R"***(íëFöõ«ŒlÆÓDôTÛÖœ„œäÕò’Éh¨èƒ‘NÈ‚TûÂ¦Oº*°sÜ~4á/ûTÜ.KL±EA½ºæ9Ô	$”ï3Ú£ó=¨ó=ªÔ;×$“ŒSª3¶?Z<Ïj¥ ³'ÜÃL2rx¨÷ÙüéU³Æ+E	Ä™íJ­»µ2•[oj9u‘ r:óKæ{T~gµgµRˆ¹I<ÏoÖœ¬q‘Q)Ü3Šz¾8#ñ¢ÁÊJ§+KQƒ‘hªå$”:x$t5 CÔxb¼ÑËp±bŠ‹ÎjU˜¦Ÿ-‡f‰(¦ùÔ&zU!j>—sõ“”yÕv¸ìÉ©¶•$õ ¶ÑŒş”(;&‡ùÔårG™í@“ŸJ¾FQ>öõ§•
¸#ŸÎ»pëÅ5m©%
JŒQÓ‚°‡ÙGCRUpHèiŞgµ>D)***""\r" R"***(RƒƒšƒÌö¥I>n”rØV,ÉÆ)j3Ú3ÚV+2päRùÕ_Ìö¥I@ê)ò0³-#¯4¾gµWYÿ »NY†jùY.,›Ìö¥#5’FM=Xüi4.R@øÅgµ0¸Çgµ
#älœ;c­›Ö¡Y1íR+níV¢#üÏjœğ)½Mj6).öõ 3Á¨©Tàæı˜ó×š)²qŠZ\¡ÈÇ #9åm½ª*UlU(‡)#Ç8¤ƒ‘Mó=¨3Èªå*Ì™	À9§©ÊÔHã ~´àArŠÖ$¢š¤ŞŞµj$òÜxŒE7Ìö ¾F1Z¨Ù :ŠŠµ%O¼)õ b>”¾gµ>Qr¶MNG^jq=)Şgµ5BÚ†#¡£{zÔ*Ù¥ªä!.öõ£{zÔTAÈªQBu$®M($r*!Ç#4«&)***""\r" R"***(>EaY‰8äS#¥B$ã¥aÎqBˆ¹OÌ²÷£kg“úÓ<ßsG›îkÇ?µœÉ}…*16;R¬¹à*\Œœ¯°úPàu•3xô4åe'ŸJ›“{==A9Ü?:Ì†ŸæÀÅ+¡6 <RPyêOç@àæ¥»“Ì‡ ã§4ğÀQ‰=Jp9¤Cc·CN#5(b)¦O3$ù­8€p?*j±^”…É?áHÍÈPI#Sê:r±'ìfØõô§àuÅ09£qõ¤Kvzâ„œäÔhI<ÔàHéA-Üš>ôê‹ÍÀÀ£Í÷4Èr%¥
ÄdˆMÛùÓÒ^œÒå}I¹ jEè>•bœ&ÀÆ)5a]QøS„Œâœ²`qúĞ•ÌÛCŠ3H9#ëAf=é2?¼?
FwD˜‚—Ò¢ó}Í(ä`şf‚.IFHèi›Ï £yô™¡'94½ÿ 
‹ÌnÔá(‚\•‰(¨üÿ jS.=(3nãè¨üÿ jQ!#8 CèÉõ¦o>‚çĞQ`'©*|u¥ó}ÍMˆnä´T^o¹ MZ‘ ç8§ûÔ+9ÇZ_7ÜÔµvC½Ér}M>¦£p	§«ÖšVôÏ9ÏãN¦‰=hŞ=)***""\r" R"***(D\‘:~4ê[#‚iC0ç4È“&Oº)j!&SG›îjw"è–¤ªâLÿ çN6rh³Œš‘i†AM2±ïME’<±'9¥F9¡ó1ÎGçJ²óœşµMhKdù>¦ŒŸSQy¾æ4„Ôò’L­´àsØÔlqO9?•.VKd´d†£OBiC61šV!ÚÃò}M=~íBƒœÓ„˜M2ZPÄT"lzÓ„„Œâ‹"$Ñ=8©ìÇó¨VoZ_´ñšC	üê3Ö”HIÆMEæ·sKæ¼Ô¸N¬sŠV`¢¡Yy¦BGüjyH‘*¾O©‰ëU‘‰5'˜Ã¥O&¦M¤Ë÷¡˜ƒŠge¦~3Ö§Í²a!ŸÒŒXMWîŸ‘ƒšN;t,dúÒ†#½Deã9¤sÔÔò3&Ë œu§«g‘UDìG“pM'7"ÉfïÅ!b;š‰®=é¢bÇ­%&ìO“êiË»=ê69f'4¹Û&§!>µ›õ¥Ip	üir3	jX§GŞ«‰O©ü)âcØÒåfm2z" 3qšrËÿ ­K‰å•bGZPÄæ YO®iûÉjyLÚ'V`3Õ 'WÍaR$ÄI¨å2h²‚Tô§'½W^¼ÓÚ^zşU<º˜´J	ÈæŸUÄ¸<5;Îoï~´œY$Ô{ÔK3ÍfOR)r2dL»‰á¿Z~Hèjšp”÷&—³fm;–³Ó4íÍëUÄÇ±ÅqşğüéòÓ,«°àpfêMU7¯åR,£i8ÓE•9§"«‰ÏLÓ„™?{õ¨p3-+)à‘ĞÕQ+ôõ¸5›.Ì°Xô™>¦¢2ûšO5ıi¨‘6O©§#UüÖîiË._ÎŸ 8–2}M9d=ê·Ú)***""\r" R"***(*ÌOSúÕ(4KH´·B:z1=êªLV4õœ„ÓPd²ÎãëJwªßh4¢Rz“G#Œ³æÓ4¡‰ÉªÂnpçOq÷©¨ŠÊäÙ>¦ŒŸSPùÃ»S„Øÿ ëÖŠ,l±JK¤ÔK8†¡§ÍW+$”9iÁÁ8ªşo9É¥YNx&…q5rÊ}áOªË3É§yÇûÃó«Q'•“Œ†•[sP	½[õ¥ó‡÷¿Z¥.RÂ¶zS²}MWR‰Ë*ùJKBpäRï>‚ æ—ÎÇj¥IÔäf¤VÅVó‡÷çKæóÔÕ{2Z-‡§Ua/“N4r2Iè¨L¯´y­ÜÕr5(8ì*7ÜÒ‰±Úš¦;2]ÇÖ•	'Ô>µh#¥W!-)U‚õªßh4ñ+w?•Z€¹KÇ¡£xô5_Í÷4iÏZ|Ê‘gxô4 äf«y§ûÆ”\1Í5'n…Œ‘ÜÓ„3UÄ®FsJ%÷5j$4™k,zOªÑÜãŒÓÁÍW)6±=Ú½h>ôÔXšU)***""\r" R"***(@·óN•J-Ó'ïKP‚N3Kç7÷…>PådÔTBbG?¥o¹§ÊÊP'V `ÓÈÍVó}Í8Lq÷©ò0±i>è¥ªâàâ”NOñ~´r’âîO“ëKóæ ó÷‡çN‘Üş5JådÅ\îıi09ÍGçïÎ“9ßúÕò
ÄŞkúÒ†fêj3ıªU”ôı˜XŠ‹Í¡4y ô&Ÿ(dúšBIêj/8{õ¥óÁéT¢ÇfÉ(¨Ìã°¥gÓñªQl9Y2}ÑOW b«‰Èà@•z9ZÜj%ãĞÑæûš¯æıiDŞ¢©D|¨³“êiõYfŒÔpşñüéò\\¤´T^pşñüé<åş÷ëK9Y8r:Ó·CUÄã¥o¹§È>TXŞ=)***""\r" R"***(ƒt¨UÆrNx§†ô4ùt)23‘N†¢œr*<ßsG+Rt“dõ§=súÕo7ÜÒ¬ädıM¢i×‘šZ®.:Ó„Ìhåb&©CÒ«lg4ñ'=OãM!ò²Íœ;5/›îj¹Xr²Z*!.zS6j”ÔY&Hèiw7­Cæûš<ßsT Šä&›¡ıiàc¹¨VLåNd}ê|¢äÔ’ŠˆÉâ?…(›ª”GÈL¬ Á¥/´uüª?Úœ$\gš¥r“	NxÑ¹95˜LÒ†=sT¢¨—-êiõ
ÈÀÓ¼ÿ jµr²J*36{Ry¾æ©E‹•’ÑQyÜcš<ßsV¢ÁD™Hš]ãÒ óObiË*µ\¬j$ÛñØÑæûšÎc&“zZ¥å%ó}Í(ryÍE¼zU—Ö«”\¬NFij!/M<H˜å¨H\„ÃŠ*?0tİNóÖ…(Ÿ˜åÆ8Í '#šBA<
:s_9Ìd¶IBœ6i›ÛÖ‚íI´È•Ÿ#ŒĞ®A¨··­*±'“KVKh˜9=	§£íô¨#¡§¬˜ëÅ4»’ÚèJX­úĞ„ÔEÁêhÀ?¥=ÛdÁˆïOV%FåP'œÓ–\(çÔœnG3%Éõ4àãæ¡óÚı(óÚı)Y‰ÈŸÍ÷4¹níP#¯4ÿ 7ı¯ÒšVÜ†Ñ&O©¥EEæÿ µúP$$à7éMÚÄ¶XHÉ4dúš9;RïoZƒ&İÉUÈ<š_7	¨„u4		èh3,-Ğš2}M1[oj“ÓŠ	r$AÉ&œ²sš‡{zÓœg4jÈl²¬võ¥Gz…e;FM(RåDs‰0:š]ÄZˆ:ã“N.@¤Ñ-“4³ŸÆš	,9¨ËœûSƒ.F=ªL[%¢£2àà·é@—<gŸ\SDİîoZ7Z{zÒ«y5VD·qÙ>¦œ„œäÓh”šÔ‡rJ)›ÛÖíëG+&ãèÉõ¦lòh.Hàb–¨\Ãò}M88Ç9¦äÒFi2$Üı³Fæïš`r:óAs(&ì~æ÷üéQ‰`j=íëJ²yüéYÙ:}áOªë>)***""\r" R"***(šwÚ}ér“tM’:p—N>•\\p)Ë!<Ô$'$ZVÀ$š7CPù¾ÿ ¥oû_¥4¬dİÙa[#‚hÉõ5ÉjpryÍM›d6ÇäúšPÄw¦‡çjnöìiò°º%Ş=)Ù>¦ G^iâBÃ­+1;tdÁÆãG›îj2ÀqšMùãm4š%´‰C‚p/B¨óhdıìŸ¥-Yœ¤‰2}M9	'“Ú¢ŞŞ´å“h³!È–”1^•†—y¥fKd¾c”¢SÜš‡{zÒ«ñóVD¶L‘œš]ÌF* çr¸Ç&¥¦fä‡†#½<1Àæ¡ó=(™€ÀY™¹&K“ëRTÏzy“ªjæM’¬ƒ¦søÒ‡=ê ë¿N)L¸8-úTØÉÉÜœ8Ío¹¨DÃóGšR\Ë/òíNóG©ªë&:Òù¿í~•.&m¢Ò¶$Ğ_ĞT+7Ğ%ç¯éSÊÌ¤Ùaã4ñ'ê·œTz
>ĞO Òå2æe“6O'¹¨<ß|~y¿í~•<¬—$Ë/¿çOóyêjªÉŸzzËôr²[V- SLÄ*?7<nı) pM.SN³ç©ıiêäæ«ƒ‘OYH?Ê—)›W,y¾æ7ÜÔwû_¥9±äö©qHÏbÂËïùR‡bx5 $t4å‘–¥¡7¡`?­*ÉÎWÔâœ²“óúTr™H´²@ÍJ¬vjšÌsœÔË3m.&M»“îoZUr:“P	zpr:óRÑ›-«wëJY‰ëP$ÄSŒŞ†¥ÁÜÍ­I2}M9\ñ¨<æ¥óÚı)ò¶Ë
ùç?.ãëUÖ`É§yÍO”—bu¿¥/›îj¸˜÷4ííëG)-î'£~´¡zÔ+&:ñJ%ç¯éK†‰ÖCÒ®1Éæ ;Ò‰;ı*\,²$lt§,æ«‰˜S„„ô5´Y¸§¬ÀöªË!#ƒúS÷¯­G!“HŸÎŞ?7í'8¨œñ@fÏ&©@I$X±8¥Y3P	æ²©<uªTÁÜXƒÉ¥ r)***""\r" R"***(Bf#¡¤É5\ŒÍìYOBièÄæª‹€:T‰p@æF%Æâ;Ò‰ş•_í>ô	ÉäQÊÁÄ´®zçó¥.Oÿ Z«­ÁÆ?ÎzRäw‰CŞœ$Àêj7ı¯Ò”L¸æ©E‰]09Í;Í÷5_ÎoJ_7ı¯ÒµPb³'ó×ó§	Ob*·›ş×é@›9ı)ò	Ä´%lòiÂBN5Yn3Öœ'¥5+2|ŸSNBNrj9=éË1ìi¨ŠÌ°¬sNó éšef»ÛÖ­D9Y)•³Á§+1ÍWØ&¤Yzşj"i†#ÿ ¯OIqÇó¨KÂ9ïUdfÑhKÇz~óéU•Î9 ˜g“NÂ²%ó_Ö5ıj#2ôoû_¥>P²&ó_Ö+g“Pù¿í~”y¿í~”ÔXÉüßsG›îj7ı¯Ò”K“×5\„Y“	€ÿ ëÔ‚Vî*®wâœ²çŞ©GAò²o7ÜÒ‰±Ú¡ó=©CôùDâÉ„™9ªâP;ÓÖa´a©r’âÉƒK¼zT>oû_¥'œÕJ$ò´Xÿ ^”ÍƒŠ€I{Ğ\çŠ¥Iu'óı¨dã\ÈGVı)VBH9ªQhm+Cœò)|À:f äàÒ”¹M4‰&ó}Ío¹¨<ßö¿JQ!<†ªQ2ÊËïùRù¾æ (Ï4y¿í~•¢‰6dşo¹¥Y2zŸÆ«‰—¡9¥È£YhIÇzPÄŒäÔp1‘KöŸzj,|¤áˆ§¬¾ÿ V±å“<õ«Q¸íbÁc×4Ñ/8Ôfci¾xíT¢KEŒŸSI¸úš‡í>ôŒŸåUÊ+äúš2}MCç5cŞ—+‘:¶:æ”8ÆsŠƒÍÿ kô Ì;j(–<ÁıãIæsÔÔoû_¥(sšµÊ‹\Òù;Ô+/AŸÂ•¤Àô§Ê™6Ô›Í÷4¢\ñªşoû_¥(võªQĞ¥Ğp{â”ÍƒŠ€HOCFöõ§Ë`H°³pE;xô5X9iÂRN~”¹GÊ‰Ã‚xÍ83õÈAüéÆcØÑÊÄâL$#ÿ ­OYtjª&=Í=&#¡£RÒJÄ`Ó·ŸAU£™±Nóš— ¹Q1séNWŠ¯ç59fç´ùl.DË*àSƒ š€L;Šp˜ãŠ,Á@°%ã©¥gøãPb3šUoïn_!?ƒúR‰[¹¨7¯­/›ş×éZ(”±æïÈ&«ù¿í~”«&G­ZAÊOæ´hó÷A½½iU‰<š|¡Ê‹	&?‹ò§	2>õ@	)***""\r" R"***(›Öšˆr“1üFœ²8ıj¾öõ§,˜qO”vDşaì)ÊÇoZ®%ç¯éO0RLM‡=éD¾æ óÚı)w±ïM"Z'gøãCKÏ_Ê¢Ş¾´P:Ö‰”“Í÷4y¾æ¡ó–9j¬>Ba&N2iÙ>¦ YA ÎçµúU­räúšT$ç&£YëùÒ‰ èJ[°å±<}éÕKÇZ_7ı¯Ò© $¢£óÚı)C“È4ùX¬‰“îŠZ‰e;y8¥Àj9Xí¡&O­<8?ız‡{zÓ·¯­W-Åd~hQÓ­3Íô"‚äŒWÉì^s!YÆ84››Ö’”:Ö‹Ü‡ ËûşTåfÏLqMŞ}Ï ªLvI¹ÏOåN]ßÄj5“?Z‘\vl\âÑÎzQz(ÑœPÄ…8Œâ™NW `Š!É¢›¼zQ ©İtKE08ş!NÜ=i&ºä…¥O¼)›Ç¡¥WàQ¡.H”RïoZb¹'¥€¥§R…$´èûÓƒÿ ×¥VÇLUY"‰“œšuD’ :ştï7ÜP–†rúPÄp)***""\r" R"***(GæÓålÔšFnDŠI\š‘T}ª5#oZp“‰lîiÅ×Ö¢YëúS•uæ‘V$¢šeQIæûŠVD9¥O¼*?7ÜS–P9¤“!^ä´GJ‹í½(˜ŸJoa·¡.öõ¥BNsQy„ôÅ=$ÈÅ	2[v$¦³0lM3bšÓr1LÌxvy¥.{
ŒHiCŞ7aÁÏzx—¿¥B\çŠúŠ9I»'ŞŞ´oaŞ£ŒJä`
VB¸ÿ 7ı¯Ò7'¿J€psE“'™“+18Í:¢Gç§4íçĞQÊ„äÙ"uü*EPİjR	Õ{Ó°®H)***""\r" R"***(>¦š&{ÑæûŠ›jCz’+ïOWb8â gÒ²qÛñ§Ê‰l”¹Å'˜}OåLó1ÜP²ç­36ØúpfW4ÍÃÖ$õ©å“C¨¤,1ÁİçĞRµ˜œ‡Ò§Şóè)V\rEÍ²j*??Ú1' R&è:rsšb±læœ¬ éÍK½Ää¬?8æŒ–9ÏåL''4Û×¥3r$@À4å$ŒšŒH½@Í9d$p.Vc)¢™¼ú
_0½G+3»&'4wëQ¬Å"œ_ĞPÑ-8Ç4ÒŞHÎHÆ))¶9Y‹`šp$t¨Á äRï>‚ƒ92MíëJ„œäÓƒJ/B)Ù¢±*3“J_Ò£Ş=)7ŸAJÄ¶Iæã‚9§+†úúTsÉ4ªØ÷¹Lİ‰Ä˜ã4»Ø÷¨ñÀüéDÄqŠN&L²9¡ÈëP¬àNó}ÅKD6Ë!Ïq@“•œ s‘š\¨Í»–„¹8)***""\r" R"***(úS•˜MV rqR$Ã¯œY)***""\r" R"***(“Ó‘Èã5Úµ(›>•7%ù–w“Ñ©	'­F²Óõ¥ó}Å.]İ‘ b)é ¨<ßq@“Ô¹Ive À÷çÒœŠ®“ÅH’äv©q!²ÀvÀæ¤I8çš®$ã¨¥×ô¤àbİËJÿ İ4»ÛÖ¡I‡zw›î)r½É7œQ½½j3.=)àœQÈCDË&:ştï7ı¯Ò äPeˆ¡A™´îOæÿ µúSÖ\{U_0˜§¬€õèåĞ’Ú¶îÔµ
\`sNgÓñ©qa{†#¡§)%rj7ÜS–p(åv%²`Ät4«#)æ¢óT)***""\r" R"***(a=1B¦fÙ`K»¥<L{Õ]çÒ¤u=@¤àfÒ±9sÚíëQÔŸhÔ¹È›{zÒ«1lP‰óOI9Í5)***""\r" R"***($K@$t4Ï7ÜP%È¦âM®L­ÔàØÍB’Ø§y£ÚQr«’ooZUq˜Ô->ßJAp:SQH²$ì)***""\r" R"***(=e `ŸÒª‰sOYxíøÓäFåíëKæ{Uo7ÜSÄı±G'piùÍNŞŞµÊ¤ûw§™Gb*ÔlC%{Òï_Z‡Í÷«"3UÊ"e# æŸ½}j àt"—Í÷\„5bÂsÚ¯ıÓURlÆ— E‚-,¸ö¥óÚı*¿ŸÇNhóıªÔ Ÿxc×špb?Â«‰Iœ& `Š\¤¸²ÊÈ ê(ó½ÇåP‰Á£xô5J$ò²À¹ c—Îj®% ıÚzÌ™íøÕ(¤¶'ŞŞ´ooZa•{O7ÜUX†™&öõ£{zÔ~o¸¥¯sM ³½½iÈæ¢óSÖ”L£¥]&‰Õÿ ¼iŞ`^U¾Ò=©ÂlŠ¨Ä­Éüßö¿J<ßö¿JƒÍ÷o>‚©Ä,X2)***""\r" R"***(ŸüŠ„L@Æ*E¸ v©åDÙıÁ§«œr*!>{R} ÂŸ#%«–’EÇ4½½ª"“ŒĞeQjÔYº.{R‰NzÔ>y=©|ßqUìÙ\¨°²3Š‘ÔÕq'Ò7ÜU*bå'òiÁÇ~*¸‘=iË6ïJµLvĞ±EF’Œpi|ßqUÈÅfH†€ì:óQù¾â”J½Í
fL²€(óÚı*5=hóS¹ªäl9IÃüÔÉ!MVYÕ ”ƒúSQbh¤ç)»×Ö£,1Á›Ï ª±<¨—zúĞGz‹yôÏ‹*&Ñ¿Jr±'“PùNElúSåe(–2CED’ã â$õùì:?xô4	€š‹-Á.})D«M>Q¤Øê]Ì;Ó<Ôõ£ÌSÒ© ådÈëOŞŞµ‘GoÎæûŠ¾[E’nô¢B@¨¼ßqG›î(äcå&±8§ooZ%çµ?Í÷ùr’‡=éâF=W¾N)ÁÂô"K%Ë	'Š_8{Tbã4o¸£•Ù–Ù8¥ó=ªliÁÈãr ä±adxõ—ñã¥WYxíøÓÖ`¹ÊYñ×ô¥ŞŞµ ‘OJ‘%À4ùUÅfME3Í÷qéWÊèÎŞj??Úƒ.î1MEnIæÿ µúR¬Ç<TY¢”?¦*¹
²&óš•df¨Dœr)ÂQ€QËaòÜ—{zÒ‡=ÅEæûŠ<ßqUËÜ\¤»Ï÷iÊÍJ‰g cŠ_<v(‡).öõ§	ÈÚ*?Ú”KôªPNflr”T~<Š~ñèiò²ym°´Ro† 8§ÊÃ•Pwt§Ôblœb—Í÷J!f<:SĞ“œš‡Ì>”ä“U(…™:3“K½}j5|õâ‘¤U«³%Éw¯­(”~•›“Æ)D‡<Š«h.[‡$dõËÇoÆ”HOLQd2q/J]íëQ‘špQBVš àæ”9n…% àæ¾@ş¯r°ÿ z€˜9ÍòqŠu+¤MØQE])ÈO<ÓièAè*Ói@À ’{ÒQGºÈrLz}ÑKMFè¸§T²o¨QE&Ââï>‚ŸQÔ„àdĞMìƒšMã8£Ífm÷¯ùÒòzÓW` ´êsAJ¯JJ*·D6‡«ëKMVQÛ»×ÖÒ!´9[SÁÈÈ¨Á¥(|b‡ª%´L¹+ÖŒÿ ´)«'Ê8¦³Œş5NM†£~´»ÍDFjAŒò)»äIE7Ìö£Ìö¤G0ê2}i¾gµ(`xï@)NJmÂuï@6‰CéFóè*1(=.ñÜRd7aå‰¤¦—…gµ29‰T½i‚˜Fih%È]çĞQ¼ú
J(ØıØş!øS·ŸAQSƒäãZár@äœSª0psNó=¨µ‰rLp$Š]çĞSC}éh!Ş})U‹u¦R«mí@›%ByæQ£Ôï3Ú™7cÃ0)Á$T^gµÆy;›#Ö{bÈ6Œ
x9¤KlzôJvóéLŒR£dç(3l–“#ÔRÈÆ)´¬Œ®É2=h¨ÁÁÍ<8<w¦K“”1^”„Ö›æ{RkB‰Q‰Í81È«A}ı28©ådó’ù¾âšÒdõ¦QŠiårT~iâ` ¨UÀàÓdP–¦m’yşÔß3=
mì‰»dÊùëŠ~óè**w™íRÕŒ›¼ú
7ŸALó=¨ó=ªl˜]Ş}Ï ¦‡é<Ïjj$7¨ıçĞQ¼ú
g™íG™íúÕ[B‰’\–—yôH1ÍP¥ffÇ–Éäş´ªøãµE¸?"œ®•®fÙ&ñèh2(ëQùƒ°£Ìÿ gõ¥dCdÁÆ2õ¥ó}ÅAæ{S©r‘rQ&OQOÏŞıj3Ú•\f•™›y©#|àqPyŸìÒ£Œ_J–®f÷,dzŠPøî?:‡Ìö£Ìö¥Ê"ÊÌGQN{UÒAëš‘d_áœYH“yô¡Îy™şÍ@O"—)“²'GÏZ‘dŒşU]`ÖcåüóC)***""\r" R"***(–VN8Å<0ÇŞÇãUVLu©œt©q2,,¾¿¥?Í÷[$t5%¦d¦LŒd~™=sQƒƒšw™íG.¢wè<1éCúŠÌäRï_Z|Œ‡æJ’(94ğÀÕpÀœNWÇZ=™-X°ŠzÉÇ­@% ¥ó9éQÈC±>óè)D‡<Š‰dãÖ—Ìö£‚a/:Q.;Š„:÷£zúÒäbjå‘8#i|Âzb«qiŞn;~´¹Y.$ûÏ £yôœ´yËO‘‘ÊL²T‹/½U©8©EÆ(äbh±æûŠ<ßqPï_Z7¯­Œ,É„§±ã/ê‘Vœ²+sO,ÉU‹šZ`•AGœµJ ‘2>õ<H 5]dÏ"”Éïš¥ ±9‘=iÂqÒªùÔ¢OÂŸ³@‹bUíO2àgŠ¨$ü*C&H£’Âq&óı©D§±\L¤âœ$Psšj´Xã®iDÙ¨ªx¥ó=©¨E„—ãò§	³éU|Â:Ö²zsT¢ƒ”¶’sK¼ú
®²uç4¾iëUÊƒ”²³1ŠrËš¬³ 9§¬‹Ö—!-4Y`cyşÕœ£GœµJ$ò“ùşÔá =J®$fœ	)***""\r" R"***(RˆœKáGjàœqUù'$ÑUÈK‰gÍ÷	=j~Æœ®3Å5r“o=…&óè)gµgµ_(ôd g’ç¥BdÏ§,Š´ùt‰wŸAN9œ´yËE˜ì‰üÿ jQ)=Wó7t­=fP¸Å¬—ba!h/è*/9})D™ÅZ‹3dÅ˜ô9õ§9àTOÂŸæ{V‰
Ì~óè(Ş}3Ìõ­.õõ§f4˜íçĞR‡$à*3"Š uÔYVD¹¢—põ¨Àğ9[wjÑE)<lFrÔíÿ í~µ r:óKæ{Ur‹”›û_­‰èß­BOZz¸Ç«Ù‰¢@äSƒ3‘QyÔ»×ÖŸ#›&Y1üªDqÜÕ]àtj•[?tÓä‰gÍ÷µWÉõ4dúš¯fO)cÏö£ÎÏ*¾O©§+Á.@ä&ƒß­/˜OLT;×Ö•\ãÒVZ‰ad'§ëR$•^9:ñOzSH®Bo7ÜQæûŠ®ÍÜ2}M>[‡!cÍ÷« #?Ê«‡ÀÆ)Ë2ŒSä)E"}ãĞÑæÓ5œ´¢LŒG ùI~Ğ‚FÏZÌÿ f3Ú´Q)1b:·ë@~~÷ëP‡ÉÆ)êprjìÔ	•ù´ıçĞT*ã9ï3Ú¥ƒ‰2I=©|ßqQ#Œşï3Ú¦ÂåæÓålòH¨ÃƒÖ”z9P¬ÉUıóR,œ{Uulb¤I>^•6b³'#4SO”qKæ{S'•¶L§)***""\r" R"***(=Xš€ŒŠ“$t5I7˜£­Uìj“ÔĞH&¯•‘ù¾â3éPï_ZE9ªH|¤ûÏ ¥YH<Š‡ÎZ œUd¥6}(Ş}*ÙÏàFI£•¢IæûŠ<ÃíQQ’:|—™8`G$Sƒ8ÅB¿v§ËaõàA9¥£4ùDÕÉ|Ïj<×õ¨üÏjRéÚ©D|¶æ¿­F'Ó7)ïKO”,Hç†ıiÛÏ ¨ÁÍ/™íUd
$«)iÂRİAæ{S£“¯ÔC°®[¡4~5JQKç->V‚ÖÒ”?cQùËéJ$*¹n&‰C:Ó–AŒÒ¡½èŞCO“B-bĞ—£Ì'¦*ëÍ9[oj9GÊÏÍª(¢¾ş©æAEP.k…(œ
JU škc6Ç€AN£îŠ``İ)ë´ió¶gµ4œœÒ±ä
@84stIOÂ¤¨Ğ…éNŞ=)***""\r" R"***('«%î:ŠnñèiCBlWÜÒ±ÜhPSJYoÈU'ÜNCG«ËäĞYHéŠh9ÍF2hx89§yÔİÊxiT€yÌ¤Ğåmİ¨çĞ~t×°£Ì†‚Ç{“E ƒĞÑT™aNWƒM§)\`Šz“Î8¨ cµYÓ½Ò–šiÃæ†®fİ‚€psNb¸À¦Ñd$Ğï3Ú3Ú›GÆjlÂèw™íJ­¸ãĞ <‘NÊ„RøûĞÍ´ôíH®«ÔÒ3©äÔŞƒ¼Ïj<Ïjxô4¡Á§fA"œŒâ–š®0: y4á³©«uĞÀ3Ò¤¤F*ZwHN@iÁòqŠA·©»“û¿¥&îG5Ç§Şúˆ0=èÜCH—"B@êi<Ïj'ÿ ®”=1T’!É¶ “ü4d÷ï—¤Èõ§£3™ÛÀïKÏ üéªà
pph²1"}ÑH_¦Ó”©àŠd¹1Àäf¦NŸB1ß4ğàû}i4ŒÛ%'4ÂùÅ7#ÔRäzÔØ‹¡Sï
x89²ƒ’iŞjzÑb¸î´S|Ôõ£ÌSÒ‹3'qÔS|ÁèiÀƒĞÕ%¡›v
rtüi´å`)***""\r" R"***(¨‹¢84QBBnÃÃàc ’3Ö¢Ş=)***""\r" R"***(H%^ ¥ÊÈrh¿Ö‘±Ÿ–›¸g¥¡Ä‡ 4ï3Ú˜\
MãĞÔäIæ{Qæ{S7­&ñèh&ägµ*¶îÕñèiÉ"Œæ7¡&HQMóSÍjzĞe)1|ÍœøR†,2j2CŠ)5s&îJ¥ó=ª5`)CƒSf"Pr3E48Å(p}¾´ÔIrHvI94ààÔy¢—#ÖRor@psO)***""\r" R"***(@$t©ÆsG)Ä”ªÛ{S7CFñèhq„ ƒÒ„œäÔJê½M9X7JJ&oBZr¾>÷çPÓ•€4ùLİ™2·u4å~0ß@$ äfœ³) “O–ærŠ'A§£œqP ğiâLT8Õ‹.:SüÏj¯¼f¤óSÖMHm¢O3Ú•d9À˜´«"ç4¹vJX	¢š$CĞÑ¼z±dˆI8'µ:£IiŞb”šw!Øxsœpnâ£§½(=Á¥Ër¹(sy¥ó;b£Rùˆ¥Ê„Tò2yIA$dŒS•‡CQ,ˆ3Kæ§­>QY“u¢¢Ü=jLQI@Í¡á9âMóSÖ5=iòˆu*±sÅ3ÌZ]ã£–ì-rMëëFõõ¨·/¥Ôt\—‚%Ş¾´© ÇÔhéŞœ1‘úQìÆÒDgµ=\cPo†ãĞÑÈÉ,	0sŠzÉ‘ëïUÖEŒÔ‹*íëUÈ4‘/™íK½}j/5=iwŠ¥ q'ó=©Õº·J~ñèir4!İ)CœóLŞ=)***""\r" R"***(Ç¡¢ÌZ2Tq‘ëéOó=ª êhÈõùYùÔäqÚ«dzŠz>y-O•Ø9QgÌ `O3Ú£YsG˜´Ô+‰Hâ$ÈÎ*¿š´¢A3UÈ&‹
r3J	*cšPàĞ¢É±a_ªU|©ª¡×¤¸<Õ(‰Ä•¤Éõ¤ó=©HñŒ~”İëV‘Ÿ(ğù8Å=IÈâ¡YjE•3ŸJ´ƒ”–—sõœôyÉïO”9Pú)‚d>´¢E4ùDÒJªO Ó¨:Ò¬ñŒ÷¦‘$ªHêy¥sÍDncá*®@h8î*A'Š¯æ§­(#i¤Ék±?™íGš?»P«&pM8¸#­A‚‰ ~zRäzŠ¯¸zÑ‘ê+E å,dzŠMãÒ¢YzRù©ëT©Ü9Q'™íOY3ïPy©ëJ$R2)***""\r" R"***(W&ƒkBq æ3Ú£‡¿…)u¦£blÇùÔ¢SŞ£.´«"c~•|¨[%dÖ—Ìö¨Ä‹(Ş=)***""\r" R"***(
7+&GNõ*9Z¬¬@ÈïR¤€pZŸ ù	É'­py&›¼zvaËb^}çG>ƒó¨Ã‚ir=ir‡)"±$SÕ²qŠ…HšrÊ ò)***""\r" R"***()DI=iáÈëÍ@²©è)***""\r" R"***(8K‘Ö[•Ê‰¼ÏjC(¡ÈõdzŠj:‚V%3ñIç5G‘ê(Èõ\¥$LˆÎiDœt¨2¾¢¤`r(å‘($t§ÉÆ*?53ŒÔ›ãôª³˜àpsNó=©ÔÒäzÒ°Ò]GÉÆ)áÈ¨Ôàæœ†„×b@Aèij<ƒĞÓ“ iò»”’>ôêb0óNŞ=)***""\r" R"***(+4ÇÊ($ŠzŒÔ{Ç¡§,¨3CW'”™I#&b¢YShæ—ÌZi*,	8v§GJ®²zSÖOC­ZV‰)$òM&õõ¨ÚOza$õ«³+&ó=¨ó=ªrÁÏ4ìÇÊÉ<ÏjUmÇ¦R© äÒhH÷æ¤Ysß5`iñ•ÆsT•ÅfIæ{Qæ{Sr=E¢ªÁfHFiÁğ1Š„c9íN `f˜(’yÔyÔÍãĞĞõJ#å%§yÔÀàõãëA#f´Q`Ğğã<Š]ëëPRƒƒ“O–áÊN®7qNó=ª à÷¥Èõùl¤áèiÊÛ{Uuu'ô©Õzšb³¹/™íG™íQù©Œæ1OJ®F>RO3Ú”JG*=ãĞÒƒ‘š¾På&Yıhó¥F® Å.ñèhå‚&ØëRG ïU•ˆêD‘z9Fá¡ùÀXô™>¦Š+óÓúe´>¦”9ızJ)¦O3qõ¡[&’”NUÑ.c•³ÒûÔÀ»zRœv¥s7!ÛÇ¡£xô4ÂÀI¼z1/˜LÒ†$g&¢	 ¾_ÈÕ-»’y¸8æ•e÷üê/0{Ñœö4îÉ,	7wüéş`ô5å`Fqõ¥ÜÇ×ó¥s&Ù1p}hŞ=)***""\r" R"***(Dç’iDŠO‚%	â—'ÔÔjÀ7Zvñèj“3m\vO©¥WÇ\šfñèiCéTCz’«ñòš2}MG’:2}M4‘™&O©¥Gz‹wû_­(‘@äÕ(“ş¢L÷5‘MÇ¡ bÀqŠz¶5X1ÆA©2Ş´&HÒó×ò¤ó}Í2Šù¬<I“ŒšpnrI¨ÁÁÉ¥Ş=)***""\r" R"***(&®'"MãĞÑ¼zxô4o†TMÙ&ñèhŞ=)***""\r" R"***(G¼zPÁºSµ†˜ıãĞÒ‚È¦R«ªŒ@î‡‚GJ~ü(çğ˜§¥bÔØ—-	D™îxqŠ¯¼z_7ÜÓJÆm“ï†—Í÷5c¿­;ÌSÒ‡¡)Ü—Í÷4y¾æ¢Ş¾†ãŞ¥j™dãüiC°9ÍDŒ2)***""\r" R"***(;xô5VD9hJ²18&œ‡CP	lÒù¾æ©#'-K!9$Ñæz‰dÈçô£xô4ÔDäÉD€)áÁ¨‚qOV)Ù
ö'Üq€*Ş£(&—ÍOZv%È”Iõ§" óSÖ8xşu<¢æ&2óåK¸ã˜=éVQI£”†É2}M(b$Ó<Ôõ Ê¾´’ “xô4ånâ¡óSÖ*ö5\¤·tM“êiË!JƒÍ÷4äqÔš\¦RdŞoÖ7ÜÔ[Ç¡£ÌZ|¨ÍêKæûš<ßsQ‡SA`;Ó%»y¾æ•e÷üêãĞÑ¼z	l³æûšœ¿Şıj “?ÄN,OzM\Í²ÃH¤pi7ÿ µúÕ|ŸSJƒ’M.TKdûÿ Úıi<ßsQy‹G˜¾ôùlD™(›¿/ŸíPïôyŠiräOænb•Xj$`:ş”»Ç¡¥f+–À£xô5 tŠz¸Ç5<¤2O1}èŞ=)***""\r" R"***(F$^”o†…7¹)—ëJ²ÿ “Pï†O”–‰^zşT,¾ıê:4X‚7ÜÓ’^Îj)***""\r" R"***(ãĞÓ‘ÔrM>PlŸÍ÷4y¾æ¡iëI¸úÒ±™?›îjd—¯&©«ã®jE”­úÑËrYkÍ÷4y¾æ«‰AèOçJr:9lCv'ósÆM*¹ëš…XmëR©G4X–Û$I1R,™ïPSƒ`HzNÉõ5š´¾o¹£–æM\˜9ï7ÜÕ7ÜÑæûš\„Ø°& äNäòj°—#£¿ëG)-"Ø˜„Ò‰Êô&ª,´á6=hp¹)***""\r" R"***(ÒbÜ“N‘Ğš¨“ƒŞ—ÎŞ?%r—|MrƒÆªy¹îiË"ã“G#'”·æîGçFÿ ö¿Z®Ñ¿ZpqĞæ…Z,	cšzÜy8¨ªzRïùH,³ëG›îjøêß­'›ÏSG!<¥¥—ÔÒùÃ±?TãœšrË’)***""\r" R"***(…(²×›îiwÿ µúÕo7ÜÓ–e#š,6‰¼ß­(œ™¨DŠiÙ¡ªåĞD¿h4¢RG'ò¨hÏáJÂ²'ãÖ²ü£¯áUÃëKæ}i¨‘`MZx™q÷ª ›¿ãO)ïO‘¡–’b:Î¤ûA÷ªÛ×Öƒ.OÂ…L‹?h>ô} ûÕo7ÜĞ$ÉêjÔI,ı ûÒ¬ù<š®®3Ë~´»Ç¡ªä@YÑ¿ZzËïùUO0™§¬£<ŸÊ§w¹lNqÇ†bÇ’j-ëØÑ½}iX,N®1ÉÍ(”™ªşj7QçïÎ©Dmf7åJ'ëUD‹M/š´ùD\}êTœºxªbOsR, ?Z9Dµö†'4¾kúÕ0{Òù¾æ­@\¤âf&œ'ëÖ«y¾æ”IÆwVŠqL±öƒïJ''½Uó÷gûF­CPöe±7«~´å›Œ†ª‰"÷oÎæ(İUÈ.BÏŸíHfõ?J¬fç†ıi<ÓœäSTî.RßNYxêj¢ÊsÉ§¬¼uüª½ˆå-yÔõŸÇj¦$ç©üiÂb7~´{1ò–üîy‚sÖ«,¤u4y¾æ´P%Ëo¹¥ßş×ëU¼ßs@“?ÄjÔÙ–Uùûß­;xô5]÷©Û÷¿Z|¡ËbmãĞÒ‰BôO©¥Wï55²,,Ä)|×õªâQØš_7ÜÕ(E“ù¯ëGšşµrFA4åaĞš¥Y“¬¯´sNY}OçP{2}MW ùKk&G_ÖŸæ§­TqŒšx‘z(–|ßsG›îj¹—'¿á@—¦Ÿ"+°%ÁïJ&$ğ*¾O©§+zş4r)***""\r" R"***(A"Çšş´y¯ëPïÿ kõ£q=õ£‘•Ê‰ÄÌ:“øSÖSİ‰ª¹>µ&à:7ëUìÂÈŸÍ÷4y¾æ ßş×ëJ²(š,5É„™îiwï~µåõ§«€1K”\¨vO©§«ñß­E¼zPÀÑÊ
(°o­?x÷ªâD=éL¹=ÿ 
j)E™îiD„toÖ«	qÜÓ„ÀhpYy4¾o¹ªâE'ƒK¿ı¯Ö§TYYiŞo¹ªªä†§+±ïO“@å-¤Ùõ¥ó}ÍCiÛÇ¡©å+&YTiÁÔôªÛÇ½9\Ö§”\­VE§	G@MW.´	 éš¥rÕÆ¥(—ÜÕa+c­9$'€:µä,oÿ kõ£û_­E¼Q¼z®R¹Q.ÿ ö¿Zr1È q¸§,˜=hqRÆO©£'ÔÔ"L÷4»ÿ Úıjl¤¹>¦•\¯Rjÿ í~´ªã¹Ík‹—Ro7ÜÒ‡Ïñ~µñèi<Å÷ªåCä,,˜M;ÎÅWY{N;Šj"ödû‰ç4õ&¡vÉ u=êìƒ–Äo¹§n>µ`jMëëL\£²}M>¦›½}hŞ=)***""\r" R"***((Éõ4dúšäïMó}Í4®$ÁØt4¢VïŸÂ¡p	§!'95iXRuw9§	;dÔQ÷§UY”™\c“šQ'`MB;ŸÂœ¥}h°r«¾´¡Á¨ÁP0)***""\r" R"***(.G¨¡$ÇÊLb—x¨2}iÛ×ÒŸ*‰ùÑ½}i¥‰ïJvtÌò+ótÓ?£…Éõ4ªIa“IŸóŠTûÔî‰rFHèh¤Ü£½9BNriÄàdÔaı)***""\r" R"***(÷&•®ÉæB¹ñIŒÑŸóŠ)İ"n&=)***""\r" R"***((Ïz3Ú”lÇ=i¦Æ› „õ§ e Ğ@Æh»&Rb”dúš@AèijÉlU$·Zváœgše*Mrd‰÷…>˜„iÛ×Ö©l`Û¸´d†“zúĞ=)***""\r" R"***(Q"äúš2}MPKm&Š(ªLWcÓîŠZj°Òï_Z«’É(iCç£‹zúÓ£eõ –M½}i†84Æ`^qLó±ı)¥s;dúšPÄµöõ£{zÓåb$Ü}i2}M0ÈGSIæÿ µúU™+c©§èjïz:š–…Ì?'ÔÑ’i7¯­×Ö¢Â»:r°Ç&˜IÀ4¤ÔÓ%¶‡ï_Z7¯­G½}izĞ.fI“êhÉõ4Õ,ßÅNé@›M;zúÔe—¹£zúÕ(¢¹ qœÍ.O©¨ĞŒƒ)û×Ö“VdV-Á§p)ˆ@9Ïjvõõ¦˜šC‘€ÎM;zúÔ{—9Í×Ö´IÖ¤›×Ö”7‹zúÒ‰;¦¢ˆdÊã1æ—zúÔ&B:šO7ı¯Ò¯•X–É÷/­—Ö¡ŞÇ½<İ)***""\r" R"***(&š&ì“'ÔÑ“êiÔÑ½}iYİ…Éõ4¡á“MŞ¾´o_Z®TKd›×Ö•[Š‹zúĞ$¡©±D¹oïrÈsŒâ£Wõ4 ƒÈ4X†É<ÁıãFğOZzúÒ‚J,A(b;Ğ\šb°É¥Ş¾´X‰$.O©£'ÔÒo_Z7¯­2%VâŸ½}j¸e=)***""\r" R"***(I½}ir“!ìÃnãêi¨SCäç<Qkİ‰’Ã&”¾:SAdRnQŞ‹]™9;Ü}iU¿¼i›×Öœ…SE®<3FO©¤]¿ÃKE›C•†94åcÔ”1gœH»$.M&O©¤ å³Fõõ¡DOR@ãšPùèÆ¢Ş¾´)***""\r" R"***(ĞÓå!Ü—'ÔÑ“êi7¯­×Ö¥¦„.O©¥W9ÁéëMŞ¾´o_Zi]&õõ¥¸5õõ H ÓåBz’äúšz±nµ¿÷88†ªQFoB@Hèië'œToû_¥_Ò‡È,	9ûÔô—æüª¸u#9 H À4r	» €wQæïª²äõÍ;põ¥ÈAedô9§ùƒûÆ«#v-ùÓ÷·­.RZlœI3FO©¨7·­ÛÖR\.N\¯%'˜?¼j%_Î—zúÑÊK‰2»A§	vªàƒĞÓÔĞ¢KEàòiw¯­@ ıiD„ô4ù.K‰7˜ñQæï‰_˜ş”¡ÔƒM@–L³6Š‘g'5¸ÛËRî_Z|„´XWcÑªE¦ª‡#ƒR£†‘C›EëëFõõ¨÷¯­×Ö§’MëëFõõ¨÷¯­èhä’yƒûÆ”>z1¨éT€y¡$;²U÷8©N:ãéPo_ZUîš|‚'ó÷`şñ¨w·­ÛÖŸ#o0xÒ†$d1¨CŒrh/éùĞ 4®N«N c5\8Ç&ëëV >RĞr8Îi|×õªË/=sOóÚı*¹DŞkúÒ«¹ïÇÖ óÚı)Ra´r ²,«NÉõ5J3ÉçÖŸæÿ µúQÊ¤™>¦Ç½B²yjp‘…©r IÏ4ííëP$£iŞoû_¥ˆvD„ã’i7¯­F]IÉ4 ‚2)***""\r" R"***(ZŠ°	@Í(—<TTw4ù °’pjE“ĞçëUƒ/LÔ›—ÖŸ Y–<ÁıãKæïUs/<<ßö¿J¥W)cÍÿ kô ËŸâ¨„Œ† ¹;¿Jµ qH›ÌŞ4¡ÉèMWó©ü©Ë+ÿ UZ$ù>¦”0–Í@&'©Å;{õjZ“o_Z7¯­Aæÿ µúP%ÉÆêj"i²0zœ²±Š®ç“OV `®Ar²o5ıiÁ›®j)***""\r" R"***(íë@r:óG r–|×õ§Áåª äuæ‚ç<SPAÊÉ¼Îsºœ²Á5\3g“NŞ¾µih¬°v4yƒûÆ GëOŞ¾´ÔPryƒûÆ•dô9¨¡§©Uş*|¨\¤¨Äû})Û­F†íëUÊW*&Y8äâ”IÏŞ¨·­80<w¢ÌN%…“N=©|Áıê…X‚iw¯­
-‹”—Ìÿ j”;­B$¡¥Ñªãò“ùƒûÆœ²ŒãuWŞŞ´lòkNPåe¯0xÑæï®IÆiÉ÷…>[MyƒûÆ²wÏj†€HéI¦ÅfOæïq‘·÷=}i¨üŸSNV ri›×ÖëëUÊŠ$:©O”eª¸`x¬ `š[²¹S%ó÷`şñ¨÷¯­/Z\¡Ê‰·âæïT[—ÖËëO•”‘*Ê:gó§ï_Z¯½}iU”M¬	÷¯­(|ôj‰JãKC‰åDèàôjz¶:šª	)***""\r" R"***(H	)***""\r" R"***(Kˆr¢Ò>Ş§'£M<HF©äRP[=iã8æ¡GrÔá(ê\AÄ™X¥Ş¾µu#9£zúÑÊ„‘(c)***""\r" R"***((fê0ç±§_Z¤¬¬›'ÔÑ“êj/7œn¥ŞŞµvRLŸSJŒrE½½iÈNfPå&Éõ4›©¦ooZUsŸ˜ÑÊ£ò}M8HF¦S€@2M\UùPá'?zœµîéC èiÙ‡)&õõ§=sùÔC½=F3Eƒ”0=ê@ÊZ‚§Š,É±-)f'­0Š‘ëTX\ŸSFO©¤ÈõdzŠ ’qš67¥Fsš~G¨ ,5TƒÈ©œšh ô4SJâåD€‘ĞÒäúšj :ÒÕ%ar°yäÒ† õ¤ N3úS)"EbGZPÄõé”f—zúÕrŠÈ”1ÀæŸ¹}j7ÅúR†bzÕ(Ççv1E3yôëŠü·˜ıı´‡Ğ0qLy"‘ê(R2ÌZ“™¢ŒQUrn>>üÒğ=1[1JI'&‹İ÷‘ê(ÈõÂ@êi2=E4®"L¯¨£åŒS2=h'T•„İ‡yÔyÔÌQKT™7c¼ÏoÖ—Î'ƒL¢¬fH¤dsŞŸ‘ê*$´ìQA$…€èß­*¶:0ÍE¸zÒ†ÁÈ4"ecM88T*ù<ÒäzŠ¤ô3dŞaÍ'˜¼*2Iîh¤Û$—Ì?Ş ;w¨©êr)¦ÄÉ¸äÑ‘ê)”V‰?#ÔR‚GJ¤È=)***""\r" R"***(P›°üQFG¨¦SI‘ê*¬A&G¨¡›ƒQäzŠ^µB{
X¦’Š(3l#¡©ÉéQÓ¨ÿ ëÒaÌ‡ïoZ7·­7#ÔQ‘ê*Ì;{“Ïµ9N@8¨ò=EH¤mäÕ5 7t-=HÀät¨ò=E¢¤’PGcJ\ãš‹8ïJ\‘Šh†;#ÔQ‘ê)„ÔÒdzŠ±†çƒÍ9Xç“P‚AÈ¥Ş};1]Áá‡Jvòz5@­“Í9[1O”–Éw·­ÛÖ˜­¸§d†šØ†ÅŞŞ´åÉ^M2•Xô¢±)***""\r" R"***(¤>Š{Ó‚©İL†Å^ƒéNŠh dRäzÒd&É	 S ~™'­ì‰r»gŠ7·­%X†ÅŞŞ´ªÇ<šnG­ÔĞCš$†œ÷¨C…èE9[=qAœ¤<¹=8§+drj<QFG¨¢×#™’dzŠpc)***""\r" R"***(E‘ëKæ  ­RD¶I½½iÊWEA¿ı¯Ö—y£”ÉÈŸpõ£Ì?Ş¡¢“V%¶H_<àÔtƒ‘HDÊıçC6£)***""\r" R"***(I¹¢…%¸õbNRä~£Èõ¤ÔÓåh‡rEsØÓ•²95½(ó}Å.K‰²pÄ)***""\r" R"***(.öõªâR:0§$rß­_%‘)***""\r" R"***(êKæïRn¢˜Hîi2=EO+$–¤†¢ÎE(>‡ò§ÊEÙ)r:µ'˜¼*6l“ùÓ„uÅ.R–¨±ægø…'˜¼*3éJ²dã"Ÿ)6dŞaşğ¥ŞOCPäzŠPà‚(åìXµùÓŒœtıj·˜OLSƒ–îj”t%´Ñ7˜½NVã“Pn´¢Lw‰ªåd2l_Ö”I7
ƒÌ=±NäŠ9Y,˜Hs×?CO`u\0ìiàŒir’ÕÉ–O|Ôqş÷ëU.óè*TA«“ù‡ûÂœ²g¯çU·ŸANY1Ö©GBlË ÷—{zÔ+%;Í÷."$ŞŞ´ªÙêj/7ÜQæûŠ@œ>:5g?z«™3ü_­LüêÔ	h¸²äu£Ì?ŞPJGF¢F'Õ¨´[z 9š…[ e¹§yâBK)1éë!èNj¢ËïùT‹/¿åIÀÌ¶%=Ê@Èj¯¿ı¯Ö‚Ş­úÔò!7bq14ôúş5T8õ§, ñŸÊR^aşğ§+ƒÆj®ÿ ö¿ZU)ûß­©l>:0£Ì?ŞYdÏñ~´åb:SQÔ	üÃıáG˜¼*7ÜQæûŠ®P'óv	÷…@$ÉíNz\¥&‰„‡=sOq÷ª¾áıïÖ—Í÷j#æE);…/Ú¨üêº6î¤SªùPÉ¾Ñî?:_9ªç"‘ê)rBU³õ§‰yÇãP ğE/›î(ä“,«óÎ)â\u#óª©/½=\¤Rä‘m.;Rı úÎ«¡óúÒäzŠ®DM‘`\Ú=j€H À"—Ì=±MBÀ’DâRFKRï'£T!‘K¸{õ§Ê2ua†§#­WØ§†ç†ıj¹.;6Yó÷©<ÃıáQdzŠ2=E%¬›Ì?Ş¥Y<µBE/›î*ÔF¢M‘ê)±¦¢ó}Åo¸«QÔvDË)¯J8=xª¾o¸§¬¿äÖŠ$8“äzŠ2=ECæÓo>‚«Rpü`0§©y5[Ìj<×õ¡E”‘g#ÔSƒpj°Ÿ”¢c¢©@c{zÓ÷Zª%#©§oÿ kõ£‘‚M“äzş´¡€9U}ÿ í~´Ç;¿Z¥>RÊ¾[ï
xp:0ªªär>´á&?‹õ¦ ÅÈYGòÃ¥=\/qùÕT“'’*Dlç-úÓPbåE)He,x5á‡-úÓ—jŒnıj”A+ŞŞ´á3ÕG­_QO‘"¬™:Ìvğ)D¬{Ô!Èb”9>”(jªÄŞaşğ¥ æ¡Èõ ú×”N$»ÛÖœ„‘œ÷¦P	)***""\r" R"***(¤ò“+òiÊàæ Ş}(sÁ8ü*’Çš½ÿ j÷şu_yì)7ŸAO”¾DZW)***""\r" R"***(ÿ ë§ÆÀ½U³Ó4øË`óG(œ9¢”H À"«äúšr94r‡!8ç¨úR—=…C‘ØÓÔŒri5a¨’+pêp}‡#ÔRî£~´%rì‹ ú~G¨ªÊíÓùS²}M£å'Èõ»€èÂ Ü}iCƒÁªP@ÓDêÄ°$ŒSò;UpH<w˜Ôr‹–äèFy=©áñÑ…VY˜uæ”K“SÊ.FZYHàÒùÍQFG­.G¨©åe”Ôõ|Œ
¯¸zÓÕ†95#HœLÀcñ!#­B¤c“K¸{õ¥ÊW):°À9§#¯5_y§#±äšC•–wZ_0ÿ z«ï>‚•_ERD¸ïoZUs;úÔ^aö¥ÇÚ®×'”Ÿ{zÑ½½j+v4y¯ëO”®BÂÊÂŸ½½j²ÈOOÖ¥@ëRã`P&VÈäÒäzŠ‡yôo>‚©D|¤Êø8È>Õ"ÉÇ«É5"‘M>Qò“y‡ûÂ”IŸÿ ]Cz2GCG(r¢À>†”¹îjf9æ—9ªH—ù´ ‘È5($t§f+"UçúÓüÃıê€8î)UÉ4(‹”['“NB*ŸSJ¼õcùÖŠ!ÊÉÖO|ÒùÕdzÓ²=E>T£Ä¤tyÍéLÈ=)***""\r" R"***(ÔPÔQ"»šPÄv¨Ã1K¼ú
¤‡ÈLFiÈÄıãP+¹èiê	äçó§Ê%ÏSĞÔy'©©}*:üGîr
(¢’l¢Š*Áè:>ô¬Á{S(¦¯rI94š)
“ü\U“Í £”S|¿z<¿z¤ÄäÇR‡ b™åûÓ€ÀÅRb½Å.HÅ&O©¥
OAJS9ªæ%»¥²2Ôú€psChÍÈ“)ÛÒ1?ÃÇ®ha¸c4&ƒ˜vóè)ÊÅºÔj»NsO@Fr*¯r$Œ“œšˆ8ĞHŠoQêr2iÊøÅB:Ÿ­HŸtU&Clvóè(Ü}iÉ÷E-Zv2m‘äúšp“¥:Š°æ§$ÑEîÉl)Ci(¡7pº­¸ãµVd²Jk1›E1¼ú
7ŸAIEóS‘š\ŸZ`LŒæœ*¬˜9B:xéÍF	*AĞRjÄs²CÀÍ0¾xñ¤¢¥+Ød¦•>ğ¤ Õ'Ğ›¢J)¡òqŠuR0R†+Ò’ŠbçCÔæ?bŒ?ZĞ—$IEG@8š¹)***""\r" R"***(’‡ b”?¨¦(!FE(ô¦Khr3FHèhÒ3»Ï  ÉœRR?İ5VFrÍ‘Òš˜àÓiPƒ=iÚÄ±üúĞI={R1Ú3ŠO3Ú•‘›êUrÏ>”Õmİ©i[R¸»Ï ¥ßÇNi´SJÆm±Şcu¤ŞÔ”U%r[± 9§¯Aô¨#¥H:
±¹&HèiwŸAQQCVv%i)¢F-ŒñL¥O¼)-Énäˆ9ÍÏ ¦?OÆ›Z¨ˆ™X“ƒN¨Pœã=©êÛ{Rh‡¸òIÉ¢›æ{R1ÜsŠ-búPäTTôû¢´!»ŞŞÔ¡È9şTÑÍ¹LÜ‰D‡”IJ†¤£\ÄœÕÌzš	'­ùs $Ó•É8¦ÑO”®IEGE>FI(b½)L˜nj%m½©Êwâš„ö¼ú
7ŸAIEW)„‡4õãüj*(ål	wŸANæ  : ´$­Iæ{Uelu§ÔòÛD­')¹=ê:(åÛ'W'Œš\ŸSP©ä)***""\r" R"***(ß†)Ô¹)***""\r" R"***(2Båz“H®Íi”UÆW%G|ıiÊI5b:7·­W(6‰éwµ@²yüéâL™¦¢ÌäXW;zQ¼ú
„ŒÒÓöw3³&ç?•H²cÿ ­P/Aô¥”¹…ŒŸSK¸úÔTdô—³d¶‰wŸAJ$ óPÑB›,,„?Z]çĞU`Hèièí´ùgîœS„*¾öõ¥Wàäı(äLŸyôo>‚ ó=¨3È£|¬°$9 Èİ‰¨Aî)***""\r" R"***(=y š9'rPÌFwR†=ÿ EO^ƒéT‘J(LŸæ¿­CNó=©òDHÄàÓÃzÔgµgµRÊJÄşaô£yô`N3Ï¥->F&™:IÏµ?ÌaÒ«"œ	î(åèèYI‰û¦æ¿­B¯œ…?Z)¨•‰OriDøõªôƒš|ƒIÄüt¥óıª°9¥¦ ¥”õï<zUPãÔªÛ»UòÌŸÍZŒN3QùÔyÔr°³&Éõ4¡ˆ=j3Ú”1?ÃÇ®hQl,É·ŸAN(r*¹\¤ôèÉ9É¨¥89yªQhN,°Mij/3¶?ZpÉŒU¨ŠÍó_Öœ¬Äg5j •ÉwZ7ŸAQQT¢>RÇ™şÕ.ãëQQMC°r’î>´o>‚£E/™íO‘‰Ä•$9¼ú
‰àŞ”õmÇ£‘…™"¹&®GRjt}é¨)***""\r" R"***(G¹:KÇSNó}ÍEzuÊ‰Ø£Ïö¨è«QAÊ‰>ĞiÂW#9¨iÁğ1Š¥)***""\r" R"***(v%æ¤G<â ©#¥W)+VMæ¿­9]ˆÎj:PÄt4¹h~O©¥AÎj"rriSï
¥$Kæ{Qæ{Shªå)E2DqÎ*DqØT(IÎM=Wwz\¢åH—Ìö§È¨|¿zPœÑf¨–¿v E=rTK–âå% p1QÓ•Æ0hä)E“d†¤¨cïN ´œ]‚ÖÇ4İçĞRQB@9]³OŞŞµqÇ­>­$ÇËqw·­H÷¨Ó¯áOÎ9©v*&½:¢Vµ-O(¹Y%*¾1QR‡Ú1Š9n4‰Ö`
Ò‰èµ9Å9wgå¥ÈW-É„¤u§‰qÔãéP©`:ıj@¤ô£|¬—yôä­2€psK•˜È{
MçĞS<ÏjäãJ6'”~óè(Ş}%*uü)Ù(å-ßŠ‘½i”èûÒ¶£²“êi2Ş´QNÈ,‡ sšz8ÇJŠ•cã­4†’'¸4¡Û;szÑÈ«!ıj„?ZhRz
’…ÊĞĞäœSÇ"Š*ÒQÊX´êŠ,ƒ•'_ÂP"œ­»µRˆr“+míK¼ç¥CERHvE”~8»Ï ªÁğ1Šx9ªQ‰·ŸAFóè)‰÷E-Ur’q‘NYÿ ëSW úQT8ŸŸ‹M! šŒ’NI¢¿Ó¡û?3d…CØSi8¡!9ŞŞ´cÁ5Í'>ƒóª!Ì™[ojr¶êŠ<óšz¶ŞÔä>˜ÿ z—Ìö¦<ƒ'×Ò‚.…E.öõ¦©ÈÎ)àã¢W%ÊÃ÷¿j7·­3Ìö§FjÒbç%# £ÌÉéúÓO Ó7·­RW5ÉÉ dÓLƒ°¨ƒ·zPù8ÅfnD¢b;Qç53 õ˜‚©\\Ä¢R{ş”ä,İMCNBNrj¬ÄäN×ğ£pşà¨©U¶Œb„µ!É’‡çŠ_3ŠŒÜş”`z
´‰r$óš—{‘‘Q`z
PHéUÊO18Î&Ÿæ{Upø(ó;ãõ¡\‡"bIëA8¨|ÏoÖ3Ú¨›²O3Ú3Ûõ¨Ãäãâ@ëTš0ï3Ú•[qÆ*/3Ú‚ç°ªš%$¦ƒ6Ê ,OSN@Fr(!É²_9©VFašŸtPKmâœFqQÒ àŠjı	»d ‘ÒœÔU}ãĞÑæ{S³aï<Îøıi|ÁïPdúÔ„àf…¸íàœN¨|Ïj˜œM+äº†#éNVÜqŠ…~ğ§Ó2rw%GZ_3Ûõ¨h«ĞWdşq#‘BÃ8¨U¶ö¥ó=©Šö,'OÆU„Ì:R¬ŒFhµÅ{–)C0ïU÷·­ÛÖ«”9‘?›şÕ=ö¨È§yÔÒ²2rìN\”˜'©¨|Ïj<Ïjfm²\AK¿hëPùÔoÅ4®I!“”ŒÀô¨Ù·b’¬›¦J¥60j%m½©^ŞÔ¬„ìMæ{~´yÕ_Ìö£Ìöª³!¦Xó=©|ãµ±#8Å89Ç"•µ!¢_9¨Ôâ ''4‹&=ª¹Iµ‹‰'¦b ¬²â†“'Ö’L‡¹cÏoJ<æªÂNz~´¼úÎªÈ–Ñ`JÌqëG>ƒó¨ˆ=;Ìö¦‘-“«y¾gµWó=¨ó=¨³$±æ1Š<Ìu­@­»µ($T‰¼ÑéJ&5*¾ÑŒ~´ìŒÚ¹adÈÏZ_3Ú S‘œRÁÆ*”Lİ‘cÌç¥8JsÃUpr3K½½iò‹Bc1Ï«)=MGE¨’o3Ú‘¤ÀÏJŠŠ@“Íÿ kô LäÔtU¨¢\‰|å¥YÏE¨h§Ê…{“ùÍGœÕùP‰ÄÇ<Ó–LŒõ÷ªÀr)êIPI¥ÊUô'Zp=Áªşô»›ÖRt,ù˜íúÓ¼ßö¿J©½½i|Ïj9ÏœÔyÍUÌŸZO4ûşuJš"Ì´³y§}§Şª¤½;xô4rXE´ûÒ‰ÉéU·CJ%ÇAB€R&9j¬³0hó=ªÔ4M–<ÏjQ31U¼Ïj<Ïj¯fCEÅˆÍ(˜¦©‰ˆíGœÔ(ÊËßhaÑ³NYòr)***""\r" R"***(g‰›9ÍJ³zÓtÉ’eÿ 9¨óš©ùÍGœÔ{3;<æ£Ï~ÕLLÔ¢^qœÑìÃ”¶'qÜştå½sUâœ¯ÙM.Aò–üæô¥3Öª=éË/¾){6e­íÜÒ«Œ|Æªù¿í~”¢aÜÑìÙJ%¿7ıªp¸ã“TÄ€ö§«£4ıšCå-,äóšLØªBNz~´ñ';SäVZ°4ííëUDÇ¹§ùÕ\£³'ŞŞ´¾gµWó=¨ó=¨å2ÊÈÉï9j |1N«P[––PxÍ8L;š¨§ààõâMC‘eÅ;ÎZ¤;sNó=©ò”¸. éGÚj ˜€´å˜ƒÖfƒ”´''‘NÄg5TL@ÆÚrÌ½ÉªQAªØ¶¬@ëR$ pjšÎq×ôsÚ«jå³.OJ€‘PÑO‘”NJQpIÀ¨h§È†•Éüæ§,¹=sU¨†T_%‹^aëNYÈêj¨ZPàæš‚şÑî:rÎÌ3¿õª;Ç¡§,œuÅW"ïêsøÑæoÎ©‡$d5<1a’i¨“ÊYó–”IÜÖ«‡øhó=«HÓRÈ§yëU©Şgµ_"Rq2çN±8«ÉÆ)À‘ĞÑËa¨„ŒZ_9ª²;nëOŞŞ´¹C‘“yÍOILÕ`ç½9eÛÑi¨‹”¶“psKç5UY²8æ—Í?äÓPWRØ”w4y£Ûóª¡·sKV "ÏœéÊàò)***""\r" R"***(UHÍ<dw¦¢‡Ê‹K ã­H²ƒĞU5`zÿ :•eÇ|U(‹”µç-rÕñèiCEƒ•“ùÔå“ ÏáUéPœ)YEŸ3BzÖ¡¢‹)***""\r" R"***(‰™xÎŸíŒbªÒ‰CÍ
,v¹kÏ?İ«#AÅU`ô©@G<Óå°r–<ÃĞóøÒ‰Ütşu[xÎ1OWÀÀ­·™0˜¦¤IxëU¼ÏjxsIÆÃ³-,¸ïŠ“Ïnã5W{{Sòzæ—(r“ùçû¢9½*ŸSFO©£•)aeÉäşıâ«+âœI=M¨v,	3À§¬ ñª¡ÈëNVİÚUr¬[YA*<Ïj®®@94o†Ÿ*bI²Ï›´`<æªûÁšPA—)Ve‘sÇ4õ•›¥VP6Šz°Şôr+•ˆzËøª¡òøÔŠ@Ö¥À¢Ïš[’)CƒUùô(,::9|ˆ³,P	ƒU÷¿µ.öõı(å™`9ïNIAUw·­9eÇ¦¡på-#­H’Œ|ÕMdÏz‘væ©BÁk )***""\r" R"***('˜¼*;qH	"«‘ÊZIqÍ=eb2*ª€sR)%rhå‘6öõ§+^j‘ĞÒ†+ÒŸ)Z–m½)æOj¨®=qRy¾æ§–äò²3Ú—xô5\8n¦–©E”ŸÎ#€(sŠ…~ğ§ÓåCå± •˜âœ$aPÒ«míLvDÊÄñÚ–¢VİÚ–™J$™ ärÈAçó¨A#‘NV'ƒG+‰8‘iD˜ëPäãü)ÛøÁJ7ŠE…“ÛÖ”NsÍVó=©U³íŠµ'çût4ÌŸSAcƒÍ0»WâéŸ­ó+j<¹$ši‘ÇëM;ˆÁj*ˆrœç4åÎyÏJE iı)İØsØÒ™â’˜ıiÚhw›îi€úÓsíG&«”‹¤8I9ëÚ—ÌôÌbŠ­ˆrq#õ§y¾æ£Ş=)***""\r" R"***(&ñèjÖÄódúš*=ÍïùÔ•H— ¢Š*®O:9 ç4Ö8çİÇÖ©!7}‰<Æô¥ót¨ÃúÒ†)***""\r" R"***(Ò¬†ä<J{çğ¥óÔÓ)Ö6N²ñ×ò¥óqÏ5¶GÑ“êiÙ‘Ì‰üìóÍo¹¨ÓîŠZir@ÄŒäÓ·CPäúš’´Q%Èqq)7ŸAIE;!]W$Ó²OSLO¼)ôŒM°¢Š*ˆæaNıêm	±ÛÇ¡§+ddQÒ«ĞO0üŸSMg9éHX“Áâ’©!);;Šp9¨èÉ)***""\r" R"***(PÔ‰¼ÁèiZB8™EbæĞRÄ÷¡\ŠnáœRÕ¤C‘"ÌsNó_Ö¡÷£'ÔÓ3rdÂVîiDØÿ ëÔ>¦œ„œäÓ°®ÉÄ„¤Éõ4ØûÓª’dúš‘XíÔtôû¢ªÖ@İ‡†FhŞ=)***""\r" R"***(6ŠD6Øÿ 7ÜÓƒÿ ×¨ªJi\B–&r::SLƒ°ªQ3l~ãœĞÒ*2Ä´™'©ªQ±£üßsG›îi”U€ÿ 7ÜĞw­0z
\ö¦›Ğ}5‰)***""\r" R"***(Ö›“êh¦Ö„ã·åGŸZe"nÃüßsH$±¦à“GJµc'&Ç¬¾‡ó§ï†¡©*’DI±ş`÷£Í÷4Ê*¹Q7¸ÿ 7ÜÑæûšer¢°ñ!' š\ŸSùÔy#¡£'ÔĞ¢…vL²×ô¥ó}ÍA“êiwZ¥6MæûšPäó“P‡õ¢Lp3IDbu“şyƒĞÔ!‰É¥GzµfİÉ¼ßsJ²ûşuñéN§k©?›îh2ÄÔ>¦—qõ§ÊD¾kúÑæ¿­E¹½hAäÑÊMÙ/šş´	[¹¨Ù‡ğšMíëBL,É¼ßs@“=ÍB²zœÓ·Š´‚Ì“Í÷4y¾æ¡fÉàšLŸST¢U‘?›îiEÃŒš¯¸úÒ†ç4ùP;"È•ÈÍ81#95XK„Òı ûÒädCÿ × ±=ê5ıiÙ>¦š‹MÇûß­'›ƒÔšacI¦³Œ`®Q2a>(ûA÷¨2Ç€Z0şÿ R‰7¹ef'¿ëKæóÔşu Î)U±×4ıÃK<â:GÚ)***""\r" R"***(BO¥!AO–ìXäu?…Vìj”G™æ©@Í¶X{š<ßsPn?ŞıhÉõ5\„İ–ŞÔñ0=	ª¡ˆ§¬ƒ·ëO‘1>Ğ}éVr{Õc6)VaE?fÂÌµæûšÄ‚j?Ú”K’3K-"ÂÎIêië)Ï«y€tÍ9e÷íÚ—³2È”÷&—Í÷5_Í÷4àç±Í.AØœ9aÔÓ•ÀÕ1‡JQ)=M
Qe(3OY†ÍùUA&N2iCïPà]™qe÷üéâ^:š¦$ÇsO¾:Òä2È—¿?ÎŞ?Ug¹§ã5JM|áŸ¼:_?Úª`sš_5»š¥lî[Y¹àsKæ¿­VYzsş4ï7ÜÑÈQ?šş´«!=[õªşo¹¥[¡4ù ´²ûşT¾o¹¨`]ÍëB€Õ‰ÄØÿ ëÑçœäU|ŸSFO©ªQE$‹krÏ¿hÕeû¼ÒÓåAd[[…õëR­Ç¥R^ƒéR+ÇZ9BÈ»öƒïGÚ½Uó‡÷çG;¨å‹_h>ô¾yÆIıj§šş´	œUìÙJ%¯´z>Ğ}ê·›îhğsT U‹?hjx•»ŸÊª‰Ktåvn¦©A‘cÍ÷4¡ÉÔØS–lbŸ(	w©WÚ9ªÂlœb$ã½5
ÄşkúÒù¾æ«ù¾æ•e÷üëE	hµæ¾zÒù¾æ YÉ¥Ş}>@³&`ç&œ³’pIªûÏ ¥0äQÈ;2È˜ƒM/Ú½WHûÔn>¦­@Ve•¸ÉÁ&œ'¹ªÁıE=]Gÿ ZŸ³‘e&Ç½;Ïö¨œĞÍÎA§È&¬YYxëùRù¾æ«	ş”ås×4ÔDYY[_5ıjf#9§ç5\©’dÁ‰Í9eoâ5c	©)¤˜4‘?›îiVCœ†üê:)r†„ÂWÍ=%äsş5\1“OF§–ÁkìOæûš<ß­E¼z7¯¥.På&[¡4ªØëPù€tÍBzf©Di7ƒÅ(>†«îoÎœ’„š*×'V òjUŞ«9àş´õ-´sùT¸±ò“o†®qšXçRP ;"e—ßó4¦r;Ô!Áÿ ëĞ\?•dKöƒïNYÉ9&«ï†”HÎ(ä"ÒÍ“Nó}ÍVI¹Í;Ïö£”9IüßsNY‰éUÖPzÓ¼À:fŸ(r¢À”ãæ?•\÷5¹næŒŸSUË¡J,²õ4å÷5XHÀc4åvÆsSÈÊ±ieùG?•9]ºç5]XíëN°ïG#"Ò³c9§‰3üUXJøëR!'94¹Y|ßsG›îjŸSFO©£Ù…‘?›îiVN?Æ G¬2(ä±-jK¸úÒ®sÎzT{×Ş—Í÷4ã³%ät4å¦¡OBiÈIÎMU‚Ì›q=õ§õ$t4á'¨£•1rÜ”Hã4õ—åÿ 
¯¸3Š‘\Ar’ù¾æ”1#95ñèiÁ›f@Q&Ş=)***""\r" R"***(8OÏ"«äúš’Ÿ)j$Şjö4¢Lÿ ¨(Éõ4r‰¢ÊÉƒÔZw›îj²1È­<7<“O”,É¼ßsNW	ÍA¼zzºú~Tù4)8p àÒy¾æ™GcE
%('¹§,„Iü*,ŸSN_»V¢¬©ùØ¥2**PÌ;Õ(•X—yôğÄt¨‡JPä{Óå®~—'M'4´‘Šü=3ôŞa¾gµòqŠ]‹HÀ/"«™Î8:RïoZ{zÒ‡èL\Ì~öõ ¿Å7zúÒ3ÿ v©nCºsšiq4’zÑVdä;Ìö¤Ş{q@ÙzÒ¼SMäQERwlPäuæŸæÿ µúTtV±I«’İ‰§O9©”Uò¢™KpzQ½}J‰ŠEbO&‹XNV&<ŠÀÎ9¦*äóN
Jd¹’)Ü3Š
‚rE0:]íëAM;N€í´×s’;úÓw·­ZbædË.\{Rù¿í~•°#“Í/Z¤„äJ®qÍJ¯Ç&«‡ÀÆ*D$ç5d9"O3Ú3Ú˜X
O3Ã@¹É„J&lóPù£û¦—Ìö NDÆb:O9ªíëFöõªåds“¬ŒÔààõªÛÛÖœyÁ¡Ä\÷,o_ZBüğ*-íëFæõ¡!6LuïFõëš‡{zÑ½½kDI6õõ£zúÔ;ÛÖ9VC»&Wşñ¥b£ƒéÒ¢{Óª¬C3)w·­%r±]Wì:ÿ ºi´ZiÚBïoZr99Çõõ¥Wşé¦.btàŸÎ—Íÿ kô¨Lœt¤ŞÔì'"È”@¥àc8ª»ÛÖ•\cæ<÷ªHfZóÚı(óÚı*¸c)***""\r" R"***(.öõ§È+²À”À©LûÕaÈ§—P3š%È•¥ííÒ£i9ÆqíL.M'9ÎjÒ±MïoZ7·­G½½hŞŞµZÌÉ7·­(Z‹{zÒ«y4í`æ¹(††“=?:e#68Å
÷%±L„£Í8ÈjŒ’zÑV•÷‘ —¿¥.óĞTT	Bñı)ò"l—{zÒy¿í~•™şÕ&G¨§Èˆ%óÚı)ßi÷¨h«QAk“‰É¥óÚı*¿J]íëO•Ñ?œ1Œş4ˆèjÄŒøÒGJ9QœL{šQ0Nj)***""\r" R"***(íëFöõªQD“™‡cG›ş×éPolõ£{zÕò’Ù?›ÆíÜ})DÃ½@\ãI½½j”Q›mEÆ3@¸$àT
I4¹äQÊ‰,	²3»ô§-ÆúõXH Æ)***""\r" R"***(;zúÑÊ…tYóÚı(óÚı*¿˜}OåJ$>ÿ •>QYù¿í~”y¾ÿ ¥A½½hÜŞ´ù¡?›ş×éG›ş×éPêJO7¿¥>@»,y¿í~”y¾ÿ ¥WóÚı)CõJ!vOæÿ µúQæÿ µúTÛÖíëT dşoû_¥hõı*)***""\r" R"***(íëNRHÉ«P/›ş×éJ9¨©w0ïG(	›4ÿ ´ûÔÔæš\ö§È“q‘ŒÒyËU÷·­Î1ßÖŸ"%¤YY8£íªâCÜRocĞÕ(YûO½*Ï»½UŞŞ´å“Õ¢‚ÙhOŒÑç-Vó¸ëúR4™ïOÙ¦)***""\r" R"***(LÃ±£Îÿ kôª›œôşTåÎ9ëMA"‰/Ê>j_7ı¯ÒªaÆh{Õr"yK~oû_¥QĞœÕq/J<ßö¿JPùQgÎZÊHªŞoû_¥oû_¥W,Eª.y¿í~”«)Ï)***""\r" R"***(TÖLò[Šxq5<‚»-‰y§$Ç±íUVLS–m½OåK”wl¶&=Í8\ ¼U_8¼RïoZ9
EŸ´fœ&=ÍSóÚı)É)éšNj‹^oû_¥9f;x9ª¢_›Ïµ=eÀÆiªcW,yÍOYÉU_7ı¯Ò•dÏ½Í¶²±§‚)***""\r" R"***(VYsïNŞ¾´ùš¹`NM/›ş×éUƒ¨9Í8L§€)ò“ÊÉÄÇ<ÒŸç5VWÉàS÷·­.]JQ&æ“Æ«#¯4äsÚš€¹Ki/æı)Şoû_¥WW8Èâ7ı¯ÒŸ!\¥Ÿ=hóÀäUc(ìhóÚı(ä+•ÄäŒŠQ/©ı* rFA§‡l{Sä)E2Ø™±NAæ«,„)***""\r" R"***((÷£”|©·¯­Àäu¨<ïö©<Òx5J"±?ÚqŞ”LIÃTÀä<ÜœV¢4›,y¿í~”y¸ş/Ò ŞŞ´ooZ®T]‹I0ìqRG2óÅRBNriæOöj”‘sÎZ<åª^aõ?•9\c“úSöh”®[ñOó•Md àÂ%ÀëŠ9
²,ù¿í~”¢eïU„„ôoÒœcïU¨	Ä¶&\ô§yÍšª­¶¤Ş}Z¦+2o9©|ßö¿J„?cJXzÑÈY“¤½ëNóÚı*ºsOŞ¾´r‡+%péOYqíP	€âœwâ«”N%¥›#š<ßö¿J†>ôêT+\KïúSÖQ §§İíd
*äë1Ú1OW=MBŸtRĞ’eò¢ÊI‘R,¹=sUW úSÕ³Ã®UĞN%¯7ı¯Ò7œnı*-ëë@u9£•“ÊM½½hÀç5“€iw·­K‰j$ŞsR¬¬Çöõ¥YzóB€ùYa_ûÆœ¯ÇÊj¿œO^)ë!“úSå*1îM½½iQ¸Á<Ô>oû_¥\¿¥>B¬‹!ˆ§,¸qíP,‡ğ§+Œ|Çš\‚q&gÕ —ï~•[zúÓƒœphå@‘c{zÑ½ºæ«ïoZ7·­…¨ù¿í~”	sÑª0M(Ôr•BÏçNÑªº‘sOŞ¾´r0å'Y<šzÉŸz®²öëJ%# £“PåEŸ4€9£Îjdf§+ñó¾[!Ù,ŒÃ4á+Š…\ãå4åq˜óŞ—.¡dXY›á/«~•\1Ç”9ïO,‹i+0©c˜ÕM\ã‘S!'©¨q)EX±ç6iÂBz‡zúĞXA¡GBœ&İéË68"«ùÍ@•‰Å>TG)kÎZ œU÷·­*9“Bˆr––n>j‘fãæª›ÛÖ®Ş˜§Ë r–|å¥ƒĞUmíëFöõ¥Ê.TYó9&ÅT0â²ddŠ9Xr¦XƒÀñ/j¯™íOp8íNÈ\¥•Ÿ)Æ_CúUPàõ§—=ª¹GÊMç5V&¡Äã4ú|¨|·&Y7&æÿ µúUq‘NsÉ£”\„âPx§Ç'Š®$ÇCúRïcßôªQ4P.$ƒsKæ{Ut`:š]ëëUÈ‡ÈN$#)|æªû×Ö€Àô4(!8"È˜‘ÉÅoû_¥@†œc9«åTYYx7oJrI¦«‰:TˆE‰)***""\r" R"***(ÆÇÀ§šfóè)ÍĞı)•ø*½Ğ9¬.óè(,O’ŠbæAE! u¦–'½UâC•‡n_QFG÷©”U&O;\
dS)C0*·%É¦—Ç Ro>‚òsM]Ì.öô¢OQM¢´LWcËu¤/è)´V©è&ÅŞ}Ï ¤¢­\‹±K0hN¿…% r)’Ù(b:Q¼ú
b±'A›–£¼ÃéI¼ú
Jk1šW%±ÄäæŠE$ŒšZ¤¬.aÁA&”ıi™=3AÏjÑäH;
“š‰z¥I‘ê)™ó1ƒŞ-i<ßqG›î)j+Ü]ƒÔÒ2(äQæûŠîã"š¸\J(¢´2
]ät’Š™¼ú
7ŸAIE0àç¸§‘šŸtU$Åv(8íK¼ú
J+HØ.É)ù¢™EQØòÀ¦ùŸJkd/Ze ¤KæØ ±=j psNó=ª•˜›J¯Jg˜})7ŸANÈ†Ù.ñéI¼ú
j±n´Š«16;yôàÀH¨ù<ƒKV•‰rDªçR‡Å1>è¥§mçdªíÀ¥zÔAÈ£{z
VBæ%gôÛÚ’‚@êh°›yô¡óÁ¨ÌƒÒ“Ì=±T‘DÙ¢0!ãš‡yô¡ıER"è˜MŸJFşóè(Ş}i‰»$Ş}Ï ¨÷ŸAJd=…]7qûÏ ¤'¹¦o>‚”)a’Ôì…{‘ê)i¾_½8PÃƒúŠú
i8¦o>‚©"[$Ş}Ï ¨÷ŸAFóè)ÙÎÉ7ŸAFóè*?0ûQæÓYäÙ&óè(Ş}1_'š\QZ(t<8ÇCI¼ú
ip=é»Ï «P!’‡=Å9YréP‡=éw3š|ŒM\œÈ âIî*'`sI¼ú
j5rÇ˜OLR‡õ'»ÍW'b?Ú 84ŸhÕIêi2=ER€‹"pN)|Ğ:â«n´ªÜç4rX	šlŒb‘_'“Ôy¾â­@	²=E(p½¨<ÂzbçĞU(cÍ÷y¾â«ï>‚œÏÔ ›Í÷åŸåéUò=E89ŒU¨?ŸíKæûŠ€?¨¥ëG"2mçĞPd#®*3/E0Ê§½R¦æ\zRyã8¨ŠF¤ÎE5LVorÀœwŸhê&GP)¬İÁÍZ…‰v,} {Qö‘íU•‰84ê¥Ùô¥ó}ÅWE9I#šiag cŠ>Ğ=ª³8i7ŸAV ˆ{—¹ç"7ÜUO1¨ó_ÖŸ³oÍ÷y¾â«$g&ŒŸZ~Ì>o¸£Ì'¦*¾óè)UÈ=±õ¥ìÀ°²Üâ¤Y€9$U0ƒõ 8Ç4ı‰i²Ğ›4¾o¸ª¢P)ÂlúQìÁ"ÒJ;bæñÔ~uSÌjxb){2‹o¸¥ÿ UWŞ{Šr¹Çš…‡vYI*EsTYnqS,£o#õ¤âR%Ş}80#9	”vÇçFóè(P¸Ë"O_ÒŸæûŠ­’:Rï>‚KÌ±æäR‰”æ«ï$àÒäzŠÒ-%ÀİÚöUàÑ“ëC‚‹hÔä¸¨ªjyäö©Ç4ùPrÜ¸&QæûŠ¬’g;i|ÌuÅ>B”KAÿ ëÒ† õ]d$qúÓÃdd‘BI¬ƒ?*p›° “	qÜUr!Ø°$>”ÿ 8‚µ\OÇJ¤f;2Ï›î(ó	éŠ¯¼ú
rÈsOÙ ³'Iæœ)ÎGçPo>‚çÒŸ $Ëo¸ J;‘P+äàâ—#ÔSP¹M2ÊÌ@/›î*¶à:7ë@r¿ızÑBÄ´Ë>o¸£Ì>Õ¸#$Šz¾ªä¸$LÉåsŒ
„6y$Sƒ8§È;&É™?áR	:
¯¼ú
x'\ˆV±ef' §ùşÕTI´ıçĞSäb'dãàüóŠ®¯ëOó3éK•Ühœ0 Î—ÌúT
ÄœS äSä‰•‰84ğÅj“çNŞ}>AY–cŸ ñNóıª¼n9ÛNŞ{Š\—'•	³ÏëOY°:UpÀò>´år(äµ-,ÿ /JQ)=ÅU7jpb@9¦ U‹‹/‘Ò•dÍVRp9=)é&3šÌ´d#®(óÔTBNëNÈ9¥Ëa¨“‰ 9Å(›=EAæoÎ—ÍäÑd_+'ó}ÅÏ ¨‡°§$½©¨Ü|¬™[=qNB*!ì)U‹u£–ÁÊMæûŠ£¹)e$@:Ô‹*`U0HéR+½)Xj)–|Ôõ§	øàUMçĞSÃu£”¥X3dcÒüñúÔ9>´»Ï ­GÊJ“ŒSÁÍB¯Ï#½?yôùdL²`óNóGr*rN)ÔrØ,‰ÒAÖ¤¦«'_Â¤C×&—.ƒ·BÊ²œQ‘ê*ÄRï>‚¦Ì|¤Â@¾aÏJ…K“ŠPHïG).6,,ƒá*çš~í9X)É¦ã¡J(²²ddŠ•%ÛÔUe~9 ïTò—ÊXŞ})<ÃíQù¾âƒ&F2)Y ”w"œ&P8ªù¢”0‚*”S‘cÏö LIÀ
¾N)ÊØ<c¥RŠ@’'IOr)é62*º¶zâœÁœGÊ¶,yşÔyşÕ˜}©ÊI4”P¹Q0‘œSÖ_—µWÉ)***""\r" R"***(=s´sO•H˜HO#¢CüU¾)***""\r" R"***(8r3ID,‰ÖN¹Ÿ¼z‡ ô4ã'<
j"åD¢A”ï7ÜTÉ8âÏsT 5bepzÒäzŠ…	È§ÕÙ!r’+`äS„¢¢S´çªÙëŠ|¥¨–<ÃéI¼ú
bs“N£”®AêÙ‘J¤šœŒzU$ƒ—R`r3E09§ƒ‘š¤†¢9_¤Y~aQ„ÈÎiÕVCà§u<L¦ùÔyÕüõv}“êBBŒ“Iæ{R<ƒñM6ÀÍ1IMó=©“ÓŠ¢‡€SŠRT2>ôê¤C“
i|b•—qÎi<¿z¡s&ÆyàAß/Ş€ÛxÇJ¤ÉrMó=©Àäf£­".k’«míJÎ ?Jˆ6¤$µªbnÃ‹Â3Ú›HNjîÈs$éj3Ú3Úb™:§8¥^*¿™íJ­»µRÔ‡"Æõõ¦±ÜsŠsô•I	»’«mÅ/™íPÑTMÑ7˜=)Àäf¡Zp9«W"R&ŒP¼Tağ1Š<ÁÜS"÷$.;
äãqØP'§fG15 àç$t4»ÛÖ„Ø”Ñ/™íG™íQ'©¤«W"o3Ú3Ú¡¢­&.ro3Ú3Ú¡§+qó«0ç%#5"}ÑPÜpr#4Y‡15&õõ¨¼Ïj7ûUE0r'ó–—Ìöªşgµ:¯”bRùÅ%FiŞgµ;"9­°ìŒcß3Ú3Ú©!9¢›æ{Qæ{U%as‹Ò‘›'¥08Ç4yÕi\‡!êÛF1Kæ{T$äæŠ¢E…™@Æ)Şf{U`øÅ<ŒÓ³17™íN™çš„>1G™íM@\Åƒ'1LŞSQ0:S|ßö¿J|†m²}ëëFõõªÆL·OÆœ²ò
|‚½É÷¯­8¢ó=¨ó=©òÛaP1MB¼SšPz¸Ä/aå€ã4gµGæ{SIÉÍiÈKw&3È§	TUpH9¡øéŸzj›–<å£ÎZƒÌö¦4™÷ªöh±hÌ¤b˜\vÉŒö¥$µJ$·rc($RyËQ É¦³ç Æ©DDşrĞ% ª¬vóH$ äÖš-â—zúÕE—'¯n”ï3Ú¯’Ø•d
kÊ	È[Ìöıhó=ª”@±æ{Qæ{U3Ú3Ú©D!Ö‚ãµVó3Úƒ)#~µJoBÒÌ¸v¥ó–«FiÅóü5jÌ°d<TeÇaQ™	íM$µ¢€yÔ	Hÿ õÔ4„…4r?™íúÑæ{T×Ö3oJ9GfYI@ê)|åÆqU<Ïj<ÃéV£p²E¿9hƒĞUO3Ú&éò³æ{S–eUO9iD ŒO~rúQç-Tó=©|æ©¨ ½‹^j“ƒJ_ŒúÕA1îqO2`dŠµîäÄ€2i¦Nx˜ÁÅ4º“’j”DNdö£Ìöıj)***""\r" R"***(ëëFõõ§Ê&®Oæ{S’P:Š®²*œÒ‰Aè)¨”±ç.3Š<åªí&)…ÀéWÈ+2ßœ´yËUŒò)ÊA9@³EŸ9hó– . ãš<Ïj¾AÄËGœ¦ªyß­g·ëV©‘ÊË~rç¥rÕj)û1]––qšx•OM	È©ô§ÈŸ3Ú3Ú«ùÔäqŸÂ“ˆBs‘úÔ‘ÈNsUÖEZQ(=O-ÊH³æ{~´å˜cš¬%"œ²dzÒp(²$)ë'Ê>Zª%#”å“#=}éò³æ{SüåÏJ¨% ğ)âuÅ.B•Ëræ—Ìöª‹&=©şgµ.TÊÔ±æ{~´yÕ pzĞ$Psš“,$Ÿ7J™íU¼å£ÎZ®DR‰g9Å9ãùÕA(' SÄÃø¨äÔiceÁ9§o_Z¨²³Pd àµˆ®WbâÊª1NÚ©	€ç4á94ı˜ÔK›—Öœ&P1TÖLŒõ÷§o_Z|¥"×œ¹éRyËš¦&P1NY‰äÕr”â^ó–9j§™íG˜;Š9¬Ë~rĞ&RpTó=©DÄp5e¿3Ú3ÚªyÍJ²’
®@³-yß­9$÷ÍU‘ĞSÖL÷Í5å¹h8=iÊà9ªªwâœªQ¸ùK!ÆyôqoZ¨$ ä
zÈHÉùEÊË`¸Í88î1UVV<SÃ®95j:
×,‡LóÍ?zúÕ1 )***""\r" R"***(?ÌöªpRÎõõ¥ çúÕ_3Ú•dÒ— ZÅ¸åºTgµTIG¯¥?Ìö£+(šzÈ¬*˜qÜSÖ\ûÓäĞ,ËŠé‚@¥ó=ªª¿÷M.öõ¥È·,‡SÖ0ëUc'Ï9§¬„uüérØ9l[YŞ/™íU–LŒâ”8î(åE±2ğ1O™çš¨&P1NY1íK”®T[ó=¨ó=ª¿™íG™íG(ÒE€ù8Å=N&ª¬‡8õf-É¥Ër¹K;×Ö•\ÅW¥E¶$ZZr89ª ƒÒœ¼Ğâ;&Yó=¨§­@´o_Z;‡*,o_ZQ*Š­½}iË Ú0*½˜íbÈ“=©âeP8î*A'…,¯¡Ôµ[p(ó=¿ZµŠQ-ùËé@˜€*¨”Ô«)'ŸÊŸ*‹‰ Ï¿¥;ÌöªbRL~4á1Ï"Ÿ ùo©me
rE8JAU#™sÓµKËéIÀ9lYI:óšw™íP	8¤ó=ªyÒ¹m$éJg‘UÌ:R‰ŒÓå%Ë« Ç”8î*ª»œÒïoZ\€¡bà™FJ²+sš¢¬@àÔ¨ÀwúRå.Í–‹¦x£zúÔ^gµı¨ä).õõ¥G]İj3Ú! QÈ.DË;×Ö•d ç]e'ü)Şgû?­‚qH±æ{~´äqÚª‰Hè)ë&{æ…X³æ{SÒN:UO3Úœ®HâŸ"[–÷ôõeÚ9ª±„Ô« Ú08§ìÆ M½}j@ëµ[Ìö 8ïO|…¡*À©<Èı*¢0É§Õr"yQ`H™àS¼Ïj¬ŠPù8Å'†‘e$çîÓüÏj¬ S•·b‹jW"z“ùÔ ƒĞÔ!È§+níV(¤YN¼S¼Ïj¯æ{S•Ø)òõ4ådá×½=]q€0*¸sÜS•Î8¥d.]K+ ÛÀ§ƒ‘š¬ŒÀjE“:)Ä°½Òœ1Üf WsOVÛÚ­DO€¨¢°üæ›>±iÉ·#Ö›J§4î‰rĞ}İãĞÑ¼zjLf:‘›iÆ)7CHÄ‘V›¶#1' Rsè?:…8Å'˜µ¢w%¤/>ƒó£pÎ)***""\r" R"***(&ñèi§“šd»u¦ùÔŠ@94•¬l!ÁÁëAƒ4ÌAA`)***""\r" R"***(Y.CËäcÚMâ–šl‡$R9 qLëT‰m2JUm½ª.ôèûÖ‹b%VİÚ–›zuZd90 c<ÑEQ›c·(-gµDÄ“Œ÷¤«H‚o3ÚQ/Aô©O Ó'˜(5$œš+C>bo3ÚşÕ89§3¼zÒQWbO4¢Ìª*+D¬72_9hƒĞTTèûÕ+‹˜“Ìö 8Ï"›EX®ÉQÆ1úÓ‹Õ 89àø\ŸÒšC¹'™íG™íQï†ãĞÕZÁÌMNó=ªvñèiäIæ{Ry£û¦™¼z7CT¹‰<ßöhó=ª=ãĞÑ¼zµ\µ$ó=¨ó=¿Zxô4o†Ÿ)<Ä»×Ö“Ìö¨™óÀô¡Tš¤™Z’ùß­*œŒâ£ KT“L›±åÀ¤ó=©›Àã›Ç¡«³'™íN•p­o¹­I¹)$õ¢¢ó}Ío¹ªäaÌKFåQ“×Ö¢ó}Í@zæ…ÃÌœô£Ìö¨÷CFñèj¬É$ó=©ë.{æ ó¡§n š© z™@ê)­.xíéQo†¹Ï©"¹/™íG™íP’OSH\ŒU¤"3Ú3Ú«ï†ãĞÓ³+˜°´…D†’zÖ‘Š%»“yÔyÕ)***""\r" R"***(“ÔÕY	²VpG<SK¯jŒœsI¼zj$¶Ù'™íG™íúÔ{Ç¡£xô5I”ºã­'™íL=Aüh,ÁªPşgµ*œŒâ¢Ş=)***""\r" R"***(Ç¡«P`N%P1Gœµå4`ô5\ˆÍØ±ægµg8ÅWŞ=éÕj¶Mæ{Qæ{T‡­&ñèjùEvXó=¨2Ô~µ_xô4¡Á4rÙ7œ¾”	Aè*QAeèQCM“ùÔyƒ*¾ñèiAÏjµ‰Œ uyËP– àÓY‰<t«ä@Xó–9j©p(S‘š|¤»üÌö§‘š¬²b$Säd–<ÏjC2àâ ó¡¥g¥R…Ày¢3Ú¡$´Uò8—®)œô¨•ˆúR™uÍ
l“Ìö JGAQ‰ŒàÒ†ST¡a^äË.{æ—Ìö¨2?½Ap*Õ1İ”Q/p*¾ñèiwCMBÀÚ,¬À_9j°9¢­A¶Ë>rúQç)â«S·CZ(!jËgµ@H¨A#¥(vÏ&«•)`L§ §,€‘U·¯½9n£9K>rĞ% ¨7CFñèir”‘grúÓÑÁêÕSÌôõïN™¢EëëNY9æ«Üp~9©ä,	9ÏJ:ã#š§¼zxrG@Eàõ§‰0ªªÉïO)rŒ¶&\Ò™rzUUuOëOó½>DRDûÇµÇµ@Z|…¥rušŸæ{Uec3Å;#ÔP£aò“ùÔä“Ú«dzŠr8u§ÊÆ¢[Yºî¥ó–«£Ş¼SP4å'ƒÚœ³(¨ÀààÕr åDşhÆJ<Ïj†œŒP 2ebGz’9¥VY=*@àûSpÍñèhŞ=)***""\r" R"***( LiŞgµWŞ=)***""\r" R"***((`hå3Úœ3Ç¥W§!$òi¨cÌöıièãjº¹É5"°^´ÔF•É|Ïj<Ïjxô4¡ïUÊ>RUbyÆ)VN=}ê_Ö®6Š¥µÉÃ¶:Ó•ÕmãĞÒùƒ¯5j#åEÍâ—#ÖªooZx$tªå¸¹K àæ² y[ÌníJ%Ç­'r–ÖUÏhó3Ú«,¹<ÒùƒĞĞ¢
6-#ŒçÚ¤È=êšJ	çÒ¦Y=OåMÄ¥Ê´ålb VÏŞ4¹¢£”j%€àsœSÖOÿ ]TÈõõqM.D—-3ÁjMëëP¤ƒm.ñèiò•ìÑadàqÚ¤YTöª‰'"°n”8‡*-ï†•d ä*
*yC”³ç'­*L›¹TÓÄ€SPAÊZó“Ş9;U_8ûÒ‰I8Ÿ³H9K"Pz
Pàjºs“OVÖš‰j	o_Z7¯­E¼zBß6E>A´YWÅ=\cUOSÏ­H²9çéG)E3Ûõ¥ uªÛÇ¡£ÌÏ4(V-«mê)|Ïj®­ÉÉ©7CNÌ´‰<Ïj<Ïj``{Ğ\Š,ÇdH2=})şgµ@ŠZifN­¸ã"1=ê²N¥HŒÜœÑÊÂÌ´®HÀ¢™iÊÛ¹ÅO(‡+cƒR#ŒúÔTçƒG)¢E•màR‡­@3NiêÃ¥Ê€°$àqJNqÅDb”0n”rØ¨¢ÆG¨¥Èõªãƒš‘\g4ÜR¤”äÁïŠxô4¡Á8£”5h–”9j,ŸSNF$àÑÊO+&ôàQzT=)ëä¥.[
Ö$S¸gä9¦+ 0iêà
vE89©A·P‡®6éV’O3Ú3ÚšFh¢È	¼Ïj“ÌöªûÇ¡§håB¶·&ßíJ;úTa§)ÁÍC¶¤Ñ°ÿ 3Ú 	Å.O©¥aØ›Ìö¥¥D„“ÉíRGŞšµ)"HûÓ©ŠÁzÓ·Šfœ£Ó§ãR"ÿ D® §â‹	'r`øÅ(pzÓîŠZ³&p8¥VİÚ¡{ŠzÉï­R@¢|Fx4`zPNM5˜cƒ_Í§¸Øê2SQî>¦Œ“ÔĞG0ıâ“xô4Æ$ŠnãëZ-EÌL\Œg5_'ÔÑ¹ºf´AÌJäÁíIQå±Ô»ÛÖ­!s’(ÏZwÈj„1­875IÌ?rwô£rz~•cĞ~”™>¦­#7"bËô¨Üæ›“êhÉõ«JÄ¹\4ğàœS(ªH†I€zŠl€;ö¦äúšc©«QìÔÓ“ã5JOSŠÑäN¬­#H3ÃTA·¹¥«V3”®J®1ÉÍ.ñèj‘ĞÑ“êjÒ&èòsE l($Ñ½}jˆrÔ‘z¥<¸#c)***""\r" R"***(IL‡  œĞNM5˜À5d†ñèhŞ=)***""\r" R"***(0²ƒ‚iÆ8=êì€“xô4yƒĞÔ9>¦œ¤KS³'˜”0n”õ “Po£Qæï´…ÌÉ÷CFñèj0xÑæµV¢äûÇ¡£ÍOZƒÌŞ4¡‰kEçDŞjzÓ‡#5óOqÖŸ(œÉÃ)ïùÒª%oïvõõªP'˜vóœ)|Ôõ¨Ù—oZfõõªI"['óSÖ1OJ€2“€irGCM"y‰·CNÎzT
Ø<švğ:5RÑ‹™“‚€zÑ½GAPyƒûÆ0xÕ%qï†ãĞÔ`şñ¥O š®V‡“šBÀw¦— ri»Ô÷«Q%±ûÇ¡§T[×Ö”>z5]‰º]AÅ'˜´ÓÉ4Ö`G´'˜“xô4ô	b9$Ğ$ÉÀcUdÄŒärI¤ó}Í0¶&“zúÓå(™%^æ½qj¾õõ£x© 'Ş=)***""\r" R"***(.õ¨<Ìÿ ¥ÜØÆiò‰ÚÄ»Ç¡¦“Ïşq¸Ğ	õ§êfİ‡ï†”r3QÑ’:µs«c©¥.1š„±94`şñ«Q'rRÄäÒy¾æ˜pëMfÀ<Õ¤»Á&“xô5O©£'ÔÕ¨6ñèhŞ¾õ¶&½}jÔP›±)|îıi<ÁïQçŠkIØ¶)ò“ÍbmãĞÑæ(ëP†'£2}M;2y‰¼Å=(ó¡,GV¤ó÷Zˆ­rÀ`işjzÕO0xÓƒß5j7$JÎ Æ*ibI4›×Ö‘˜À5¯*0¾o¹¥YGzˆ²ƒ‚hŞ¾´ÔBäşjzÑæ§­A½}hŞ¾µ|£æ'óô¥ó}ÍWŞF¥ó2>÷JjÌÉüÁïM,Iàš‡ÌŞ4yƒûÆŸ³bl—ŒóN ÍAæï7¯­R¦"5=hó—ûß­@ ázš¥…rÀ—ız{J¸<Õ_3ıª<Áıê¥“ù¼õ4y¾æ Œµ?zúÕ{0r±*ËÇQøÒyÍD\cå¦™9ûÕJóù u&œ®;œÕ_0xÓÖCÜâ«“A6Y, g4†Ej#!Çjiu=M5ù©ë@vÍVfçƒJ$`:ÖŠ [YWš_5=j “#–£ÌŞ5^ÍÌ[óSÖ"“ŒÕO0xÓ·· ¦¡a§rÙqÙçFÿ ö¿Z­æïQ&xİG³‹À<·ëN®x5W'ÔÓ‘Î@©å)+|ßs@“'ïÆ 21áM'™şÑ¡BåÅ–@:µH’ÎsT„ w©rZ~ÌÑ+Ä˜õ§	Tj¢Ë¸gu89=ê\,)***""\r" R"***(¼Ôõ§¬Š3U†94¢AÙ©8”·æ§­(“ÜÕQ/`ië.3G%Æ•‹BE=*MãĞÕ@ê­Iæï,Ri<ÁïG›îj¿˜?¼iCäà1¡Ä¤Ël
O3'©bsArhQ-&X(ş#ùÓÒEëš§“êièÄÓå*ÅèÜsK¼z¯~j_0xÓP*Å¤‘qÉ¥óSÖªù£Í'˜?¼j”–…Ğã³~´oÿ kõª‚V# ÓÃçø‰)***""\r" R"***(Få¥‘x©<Å=)***""\r" R"***(TRëSFÊs“O•‘wCFñèjŸSFO©£”V&Ş=)***""\r" R"***((qµO©£qõ¡E‹ÿ ÚıiÈùïøÕelM<HÈ5\‚QL²®£©ÍH’š¥çjx”‘É¦¡bÔl[óSÖ1MUó÷©É(#;¿*®A²ÆñïKæ}j&N7r8+É§kîÉƒ3“OVÅ@<iCUÊÅfZÿ ^Ÿ¼z«¼­?ÌŞ4r±Ù“ù‹Gšµpxİ@eé¨\i\°²)èiÊüõÏãUU×wšz¹Ï48Ø¥Ê¾O§¬„uâ«¬óÚæıê\£P.	8<şto>¿­WY¸Í.ãëG*+”\ç95"¸­VY8äâ”9ê)***""\r" R"***(¬9K«"ŒÒùƒĞÕUbGZz¾xİSËb¬Ë
Ã¥Vã8ªÁ—šp”O”\…½ÿ í~´…Ï÷¿Z¯æïRùÃüŠÉr0úŸÎœ¬;çUÄ¹8È§£.î´ùEÈO¸“J® óQo_Z7¯­£ä,¤‹×4ã"œÕ@àtjz¸=iª}GÊËjzÑæ§­A½}hŞ¾´ù”Ÿz™§ãïUpÇr°ÛÉæBynÉÄŠ	§«ï_ZUCG!J%°àÓ÷CUVOCŸ­?ÌŞ4¹C”±½sŠ2=E@ŒiUˆ<š9F¢‹
è3K¼z†<=jLbR•‡†Éã5"3…Hš‘ÍRŠ°ÚV,G Æ)ÂLzÔ(Àu4íëëKZ	2zšz¸ÇZƒzúÒ‡QÉbÑidL}ê]Ê{Õea·“Í=\õ—%†Ò-+:ÓĞœšªqÁ©OCŸ­'’±`uæ¹?»úT`şñ£ÌŞ4r‰¤YV\çô§CĞUU—²18&QY2=E9XÖ««`òjDeÎsCZ)***""\r" R"***($ÉòCOPCU÷Ñ©ë&:œ}(Q¸š±5#¡¨üÌÿ §+ 94ùDH¯Øşu"¸ ¤ã4õ`fŸ ¬‰ƒpiëĞ}*“)***""\r" R"***(<IÇŞ¥Ê‡dÉFÜóOÈõ_ÌŞ4àÌsUÊãƒšxpMV18Í=XƒÉ¥È¹aİÖ‘ê*¸u9§,ªN	§ÈW+,+ zÓÒEÉªÊÀıÓOVşñ¡G %©d0=)j”ö4õv#$ÓPIfI’:’&©¨’94´4	;“ù€t&7ÜÔi÷E-%D®I¸rj@A8ÍD@ëKT¢R‰ğsĞŸÒ›ŸOåJx˜Y×ó2g§ÌÇnÛij<‘È ±#“U©/aÎÀŒM¤Èõ¹¡ªLÌ(¤Ü¾¢— ô5´BáE´Ç<õ­S±)***""\r" R"***(Ü}Rw!ÈyeM×Ö™ERW&ãÁ¡¥È¨óRU‰»Î(¤'4gµZVDsŠäÁ¦–'©¤$°Á4˜>¦´Âs¸¹ dô¨¹8&œ/JzåpQ´c4ŒX?•:Š¤ÌŞâ.qóRÑEiÌÜ¬Q‘ëFAèjˆrc× úT€ƒĞÔjF#¥-4®Hö gµFßv–‘Eh^Ã0})***""\r" R"***(¤RïoZÁ5aÏq(¢ŠµbnÂŠk6:³÷\lK˜ê)2=E.AèkHîO0S•€&›EZvaû×Ö”KÇ)***""\r" R"***(úTx>´U‡1 ·CK¹zŠ”¹íM+ä<M&õõ¦–'‚i*¹P”‰Œƒšs?)¨A#iw·­4„İÉU¹ù.õõ¨w·­ÛÖ«”–ìM¹qœÒ3œü¦£VÏŞ4ìZ¸ R{zĞ³É¤¦³ğjÒîH\ãŠMÍëQïoZrœŠ¤‰lvæõ§Ôu%Q)***""\r" R"***(¤)sM1˜cå<Ò±À¨Ø2*¹EÌ8±<HE3{zĞX‘‚jÒ(y	¤Ş¾´Ê+D‚ã÷¯­.xÍGE>T>kŞ¾´« ºÔy´™¢ªÄ¹‚¿xõ¥Ş¾µ ~Á©êÜrj”Hl“zúÒõ¨²£¡dzŠ¨ÄbSÈÅ4„i´Œp+HÄiÜy(˜YAÁ4ÒÌx&’­@\Ã÷¯­×Ö˜qŞ“#ÔU¨‰²MëëFõõ¨ò=E¢©E\d=Ÿ Ó€õ4×äğ{TlÄµQV¢q ô K“€Õöõ£{Í>D’$Òo_Z„¹íJ€j¹r]ëëJ$$ğß¥Gœu4n´ÔVK½½h,HÁ5›î)7“ÆêÓ”VhyeÒ3qòšc70Í4»õjm	7·­ÛÖ¢ó÷…9Xç“UÊ!û›Ö”ÉÇJfG¨¦¹ëÚ´ŒSb¾£üßö¿J<ßö¿J‹#ÔQ‘ê+ND2upG&”²õG­.ò3øÕ(6õõ£zúÔaşğ£Ì?Şı˜–\pi¥Ÿ×ô¨ÖOSšœöSTÄØó![ô K“ÕG¨¥Ü!…ZÁûÎ—rúÔgûB0ÿ xSäCØŸzúĞ$£Taşğ¥ŞOF§È"É“&öõ¨VO|Rù‡ûÂ…M2·1¥Ş¾µY¤9ş´›ÛÖ­Dvlµ½}hŞ¾µWyÅÛÖ«V-o_ZQ!=ª#¯5"ÉêsT¢€±½½hÜÙäÔNzSüÃıêKV'3Á§«qÉª»ÛÖœ®@ûÕ>Í•Ê™aœ
@Ç<š‡Ì?Ş»ÉèÔÔ,i‰·¯­=MVŞŞ´ôrzPã¡VDû×Ö¸ëU··­9[#“KvE‘ƒŞ£ª‚Fè¤Y9jf>VXîiá”f«+üÆŸ¹‡zjDêË×­?zúÕd$õ5.G¨£‘ÊJ<ƒN)***""\r" R"***(ÆK~à;Š_0ÿ zR’DÁÔƒKæÿ µúT
ìO&‘ê)ò&Z'WÉÉ4¢@:5BŒ¹ê:S²=E>A–ƒÖëëQ!94¹¢…ú«œpiêÀğO5´¹_QùÓjÂ'V `š]ëëP+684õ9(”“&W zÔ±ËşÕ@¤`r:R«`äO‘2‹oû_¥oû_¥Wó÷…aşğ¥ìÀ±æÿ µúP$'¡¨É –§‚©BÁ¹.öõ£{zÔ{ÛÖíëNÃå%Wşñ§£/­WŞŞ´¨IÎj”ùK;×Ö”Hz®ôõlM>T;"q"‘œÔŠË·­Uq€x§«rERŠdÛ±e\gå4ğËMUGZx“½O”E•“=óArOzšyõéO”¤‰·­*·rß†*-íëJ¬Äã4r•mI”Œƒš~åõ¨AÈ4»ÛÖ—(ìË@9Ïjx ô5]IJr·]Æ— ÔYh8†£Íÿ kô¨PúšvG­.Bµ%ÎsOW8ô¨R$‡)ò±Ù“† `xaMB®q(ŞŞ´r®£Q-+šp ÷ªÀğ)***""\r" R"***(H<\£ädù¢‚ËÜÔy¢—#ÖŸ(ù‡ ärJ3×ŸZ‡#ÔRäzÑÊ>RÇ›ş×éNWÏZª	)èç<zQa8–¡äšr…v«+g©§¬€u9üiò“ÊOED$)***""\r" R"***(ÎïÖœö4r‡+$G Ò« £&¢ŞŞ´ån9"šHI7¯­ ƒĞÔy¢–©FáÊ‹ ƒĞÓò=EARTò‡) a)***""\r" R"***(81Ï&¡EI‘ëG(š'‰—jMËëUSïSÁ#¥>Aò“–QŞ•[û¦¡V$òiÀ‘ĞÒåHiXdÀëNĞÔIÎjD#{Ñd;Üç§ò§qÍ"&—+ê(i)***""\r" R"***(+’'İ e­BãƒO"¥¦ŠJÄj@Aèj%#‘Ò–¦È¤®O½}hÈ#"™GJvB±*M=dj)***""\r" R"***(íëNGoOÆš€¹K×ÖëëPïoZUbO&Ÿ"‰ĞÔÔ¡Ç~*º3“RGŞT‡ËtK¹Ozpb8¢¥GCG(œI•àiêÀU·°4õv"š…ÅdN†¤Râª‡=êEsEdXUİŞ1j$õ55¨9Pïİç4»”œf™FHäQÊRD”«·?5F¬Å°OóG)¢JÃÔ¯E§#ÔÔqõëÚŸUml+"d u4àAéP§~iÀ‘ĞÓå*(™t'Ôõ' gŠ®Ïj’7a×Št.Å¥?/ÿ Z–£Y>_¼)w·cSÊ‰Q =N*@Ct59§!94(ÙE7Cô¦QE0-ÎÇ¢
kôüh¢´[“v6Œ‘ĞÑEY›l)À2úQEi^ÃIÉÉ w¢ŠĞR
(¢ª;’QEQ2)=)ôQZ­Éşé¦QEY˜QEqØ‡¸©×ğ§ÑE1QV‘p¢Š+U±›ÜºŸ­9Pc94QTİ‘)***""\r" R"***(±Õ%U
ì)îš(ªH—¸Ê(¢¨Â1 dSKëEIj@”à§ò¢ŠÑÛ¸l¦” ½(¢´ˆ®Å¢Š*„QETw ¢Š+H“!‘MŞ}Uv(qÜQ¼öQMì‰84ê(«QE¦À>´QE»
(¢´ è)wš(«ìf&Iêiîš(«HQE¤@(¢Š 
(¢šW×ğ¤¢Šµ° œ
xh¢©$ÑEhVBï4™'©¢ŠÖ$QT_§ãM¢Š¸ì'°QEÈäç¯jn(¢µŠw
(¢´E…QWk OSIš(¦·ÑEV‰j`Ç4Œ»»ÑEZJàö€£ ~t›Ï ¢Š´‘ï>‚†V<æŠ*ÔP¬†ÑE!…>´QZ$EU d†Œ“ÔÑEZHŠ(¢È õQE2e¸R†+ÒŠ*ì‰¤‘“HÌAÅS±ka7ŸAFóè(¢„0Ş}Ï ¢Š» ?¨§«ëEi!Y¡z­Rz0Ä”QE#Hì©×ğ¢ŠVE'¨úPÅzQEF‹pŞ}9I#&Š)¤‹²¿vŠ)Y åÜO	4QEÒM‡ZyAEr¢’Ì>”¡Û Š(¢È¤õ$·&ŸEYd#¡§!'94QNÈ,‰8æE¬%aCœ§#4QNÃ$Oº)h¢•¼Ô¨2¢Š« ‘ëI‘ê(¢‘IC’0jE84QM+j.óØRo>‚Š*¬†9X·Z|}è¢˜¢Š(C1NS‘š(ªÀ8N§œÑE²’M¨cĞÓè¢šPES)!Êù=©r=EP6ªä)***""\r" R"***(=X·Z( i!ñç?‡4ê(¥d1èIš‘>è¢ŠV@H¿tRÑEK)+1ëĞ})h¢šÜ¡wŸAFóè(¢ªÈW$âŸxQE&•À}($(¢¤yôå$òGÒŠ+D
	éÊî8Š(¶ =w3Í9zrh¢’%è8N<EX]	*J(¥a*ıáE"}áO¢ŠaÉÖEqÙ\t}éÔQWdqC‘ÿ ×§)ÈÍT´Š$Oº*Eè>”QRÊã‚–éO¢ŠQI”.óè(ŞŞÔQWÊ€UrN*D<ã4QNÚ€êPH<QE2b9I<‘S§Bh¢“HoaÔQEDİ€8§¨ÀÅSğ€ŒæŠ^ÔQ@*…©h¢¥­[…QN;TûÂŸz(¦TEN´óÅPVãĞ“É RÑE;j;kaê4¹¢Šo±¢Z^J‘z¥T±´®H½Òœ”Q@ÖÇÿÙ)***", 153014));
        res.end();
    });

    app.route<crow::black_magic::get_parameter_tag("/""css/fonts.css")>("/""css/fonts.css")([](const crow::request & , crow::response &res) {
        res.add_header("Content-Type", "text/css; charset=UTF-8");
        res.add_header("ETag", "\"md5/55f11d0e5f4a169024b28e502eed9736\"");
        res.add_header("Last-Modified", "Sat, 22 Aug 2026 21:16:03 GMT");
        res.write(std::string(R"***(@font-face {
  font-family: 'Roboto';
  font-style: italic;
  font-weight: 300;
  src: local('Roboto Light Italic'), local('Roboto-LightItalic'), url(https://fonts.gstatic.com/s/roboto/v16/7m8l7TlFO-S3VkhHuR0at50EAVxt0G0biEntp43Qt6E.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: italic;
  font-weight: 400;
  src: local('Roboto Italic'), local('Roboto-Italic'), url(https://fonts.gstatic.com/s/roboto/v16/W4wDsBUluyw0tK3tykhXEfesZW2xOQ-xsNqO47m55DA.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: italic;
  font-weight: 500;
  src: local('Roboto Medium Italic'), local('Roboto-MediumItalic'), url(https://fonts.gstatic.com/s/roboto/v16/OLffGBTaF0XFOW1gnuHF0Z0EAVxt0G0biEntp43Qt6E.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: italic;
  font-weight: 700;
  src: local('Roboto Bold Italic'), local('Roboto-BoldItalic'), url(https://fonts.gstatic.com/s/roboto/v16/t6Nd4cfPRhZP44Q5QAjcC50EAVxt0G0biEntp43Qt6E.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 300;
  src: local('Roboto Light'), local('Roboto-Light'), url(https://fonts.gstatic.com/s/roboto/v16/Hgo13k-tfSpn0qi1SFdUfaCWcynf_cDxXwCLxiixG1c.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 400;
  src: local('Roboto'), local('Roboto-Regular'), url(https://fonts.gstatic.com/s/roboto/v16/zN7GBFwfMP4uA6AR0HCoLQ.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 500;
  src: local('Roboto Medium'), local('Roboto-Medium'), url(https://fonts.gstatic.com/s/roboto/v16/RxZJdnzeo3R5zSexge8UUaCWcynf_cDxXwCLxiixG1c.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 700;
  src: local('Roboto Bold'), local('Roboto-Bold'), url(https://fonts.gstatic.com/s/roboto/v16/d-6IYplOFocCacKzxwXSOKCWcynf_cDxXwCLxiixG1c.ttf) format('truetype');
}
)***", 1992));
        res.end();
    });

    app.route<crow::black_magic::get_parameter_tag("/""css/theme.css")>("/""css/theme.css")([](const crow::request & , crow::response &res) {
        res.add_header("Content-Type", "text/css; charset=UTF-8");
        res.add_header("ETag", "\"md5/af64ba17dac9c99e38222881b4b99d2d\"");
        res.add_header("Last-Modified", "Sat, 22 Aug 2026 21:16:03 GMT");
        res.write(std::string(R"***(/*
Template: Portefeuille
Author: # using Bootstrap 3
*/


.navbar-fixed-top{top:90px}
.row-merge {
  width: 100%;
  *zoom: 1;
}
.row-merge:before,
.row-merge:after {
  display: table;
  content: "";
  line-height: 0;
}
.row-merge:after {
  clear: both;
}
.row-merge [class*="span"] {
  display: block;
  width: 100%;
  min-height: 30px;
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
  float: left;
  margin-left: 0%;
  *margin-left: -0.06944444444444445%;
}
.copyrights{
	text-indent:-9999px;
	height:0;
	line-height:0;
	font-size:0;
	overflow:hidden;
}
.row-merge [class*="span"]:first-child {
  margin-left: 0;
}
.row-merge .controls-row [class*="span"] + [class*="span"] {
  margin-left: 0%;
}
.row-merge .span12 {
  width: 99.99999999999999%;
  *width: 99.93055555555554%;
}
.row-merge .span11 {
  width: 91.66666666666666%;
  *width: 91.59722222222221%;
}
.row-merge .span10 {
  width: 83.33333333333331%;
  *width: 83.26388888888887%;
}
.row-merge .span9 {
  width: 74.99999999999999%;
  *width: 74.93055555555554%;
}
.row-merge .span8 {
  width: 66.66666666666666%;
  *width: 66.59722222222221%;
}
.row-merge .span7 {
  width: 58.33333333333333%;
  *width: 58.263888888888886%;
}
.row-merge .span6 {
  width: 49.99999999999999%;
  *width: 49.93055555555555%;
}
.row-merge .span5 {
  width: 41.66666666666666%;
  *width: 41.597222222222214%;
}
.row-merge .span4 {
  width: 33.33333333333333%;
  *width: 33.263888888888886%;
}
.row-merge .span3 {
  width: 24.999999999999996%;
  *width: 24.930555555555554%;
}
.row-merge .span2 {
  width: 16.666666666666664%;
  *width: 16.59722222222222%;
}
.row-merge .span1 {
  width: 8.333333333333332%;
  *width: 8.263888888888888%;
}
.row-merge .offset12 {
  margin-left: 99.99999999999999%;
  *margin-left: 99.8611111111111%;
}
.row-merge .offset12:first-child {
  margin-left: 99.99999999999999%;
  *margin-left: 99.8611111111111%;
}
.row-merge .offset11 {
  margin-left: 91.66666666666666%;
  *margin-left: 91.52777777777777%;
}
.row-merge .offset11:first-child {
  margin-left: 91.66666666666666%;
  *margin-left: 91.52777777777777%;
}
.row-merge .offset10 {
  margin-left: 83.33333333333331%;
  *margin-left: 83.19444444444443%;
}
.row-merge .offset10:first-child {
  margin-left: 83.33333333333331%;
  *margin-left: 83.19444444444443%;
}
.row-merge .offset9 {
  margin-left: 74.99999999999999%;
  *margin-left: 74.8611111111111%;
}
.row-merge .offset9:first-child {
  margin-left: 74.99999999999999%;
  *margin-left: 74.8611111111111%;
}
.row-merge .offset8 {
  margin-left: 66.66666666666666%;
  *margin-left: 66.52777777777777%;
}
.row-merge .offset8:first-child {
  margin-left: 66.66666666666666%;
  *margin-left: 66.52777777777777%;
}
.row-merge .offset7 {
  margin-left: 58.33333333333333%;
  *margin-left: 58.19444444444444%;
}
.row-merge .offset7:first-child {
  margin-left: 58.33333333333333%;
  *margin-left: 58.19444444444444%;
}
.row-merge .offset6 {
  margin-left: 49.99999999999999%;
  *margin-left: 49.86111111111111%;
}
.row-merge .offset6:first-child {
  margin-left: 49.99999999999999%;
  *margin-left: 49.86111111111111%;
}
.row-merge .offset5 {
  margin-left: 41.66666666666666%;
  *margin-left: 41.52777777777777%;
}
.row-merge .offset5:first-child {
  margin-left: 41.66666666666666%;
  *margin-left: 41.52777777777777%;
}
.row-merge .offset4 {
  margin-left: 33.33333333333333%;
  *margin-left: 33.19444444444444%;
}
.row-merge .offset4:first-child {
  margin-left: 33.33333333333333%;
  *margin-left: 33.19444444444444%;
}
.row-merge .offset3 {
  margin-left: 24.999999999999996%;
  *margin-left: 24.86111111111111%;
}
.row-merge .offset3:first-child {
  margin-left: 24.999999999999996%;
  *margin-left: 24.86111111111111%;
}
.row-merge .offset2 {
  margin-left: 16.666666666666664%;
  *margin-left: 16.52777777777778%;
}
.row-merge .offset2:first-child {
  margin-left: 16.666666666666664%;
  *margin-left: 16.52777777777778%;
}
.row-merge .offset1 {
  margin-left: 8.333333333333332%;
  *margin-left: 8.194444444444443%;
}
.row-merge .offset1:first-child {
  margin-left: 8.333333333333332%;
  *margin-left: 8.194444444444443%;
}
[class*="span"].hide,
.row-merge [class*="span"].hide {
  display: none;
}
[class*="span"].pull-right,
.row-merge [class*="span"].pull-right {
  float: right;
}
@media (max-width: 767px) {
  [class*="span"],
  .uneditable-input[class*="span"],
  .row-merge [class*="span"] {
    float: none;
    display: block;
    width: 100%;
    margin-left: 0;
    -webkit-box-sizing: border-box;
    -moz-box-sizing: border-box;
    box-sizing: border-box;
  }
  .span12,
  .row-merge .span12 {
    width: 100%;
    -webkit-box-sizing: border-box;
    -moz-box-sizing: border-box;
    box-sizing: border-box;
  }
  .row-merge [class*="offset"]:first-child {
    margin-left: 0;
  }
}
/*= TYPOGRAPHY
---------------------------------------------------------------------------------------------- */
html,
body {
  height: 100%;
  margin: 0;
  padding: 0;
  
}
body {
  background: #fff;
  color: #666;
  font-size: 14px;
  font-family: 'Roboto', Arial, sans-serif;
  font-weight: 300;
}
h1,
h2,
h3,
h4,
h5,
h6 {
  font-family: 'Roboto', Arial, sans-serif;
  font-weight: 500;
  color: #444;
  margin-top: 0;
  margin-bottom: 15px;
  line-height: 1.15;
}
h1 small,
h2 small,
h3 small,
h4 small,
h5 small,
h6 small {
  font-size: 12px;
  margin: 0 0 0 5px;
}
h1 {
  font-size: 28px;
}
h2 {
  font-size: 24px;
}
h3 {
  font-size: 18px;
}
h4 {
  font-size: 16px;
}
h5 {
  font-size: 14px;
}
h6 {
  font-size: 11px;
}
strong,
b {
  color: #555;
}
a {
  color: #0088cc;
}
a:hover,
a:focus {
  outline: none;
}
small,
.small {
  font-size: 13px;
}
ul,
menu,
dir {
  list-style-type: square;
}
form {
  margin: 0;
}
form fieldset {
  border: 1px solid #e5e6e7;
  -webkit-border-radius: 2px;
  -moz-border-radius: 2px;
  border-radius: 2px;
  padding: 25px;
}
label {
  font-family: inherit;
  font-weight: inherit;
}
.lead {
  font-size: 15px;
  line-height: 24px;
}
.unstyled {
  padding: 0;
  margin: 0;
  list-style: none;
}
.gap-15 {
  height: 15px;
}
.gap-30 {
  height: 30px;
}
.gap-50 {
  height: 30px;
}
.gap-70 {
  height: 30px;
}
/*= FORM
---------------------------------------------------------------------------------------------- */
.form-control {
  -webkit-border-radius: 2px;
  -moz-border-radius: 2px;
  border-radius: 2px;
  -webkit-box-shadow: none;
  -moz-box-shadow: none;
  box-shadow: none;
  font-size: 14px;
}
/*= BUTTONS
---------------------------------------------------------------------------------------------- */
.btn {
  -webkit-border-radius: 2px;
  -moz-border-radius: 2px;
  border-radius: 2px;
  border-width: 2px;
  font-family: 'Roboto', Arial, sans-serif;
  border-color: transparent;
}
.btn:hover {
  border-color: transparent;
}
.btn-outline {
  border-color: #fff;
  border-color: rgba(255, 255, 255, 0.4);
  background: none;
  color: #fff;
}
.btn-outline:hover,
.btn-outline.active {
  border-color: #fff;
  color: #fff;
  -webkit-box-shadow: none;
  -moz-box-shadow: none;
  box-shadow: none;
}
.btn-inverse {
  background: #1e1e1e;
  color: #fff;
}
.btn-inverse:hover {
  background: #2f2f2f;
  color: #fff;
}
/*= HEADER
---------------------------------------------------------------------------------------------- */
.header .navbar {
  background: #fff;
}
.header .navbar-nav > li > a {
  font-size: 14px;
  color: #555;
}
/*= SECTIONS
---------------------------------------------------------------------------------------------- */
.section {
  padding: 100px 0;
}
.section.type-1 {
  color: #a5b3bf;
}
.section.type-1 h1,
.section.type-1 h2,
.section.type-1 h3,
.section.type-1 h4,
.section.type-1 h5,
.section.type-1 h6,
.section.type-1 strong,
.section.type-1 b {
  color: #fff;
}
.section.type-1 h4 {
  color: #00a0dc;
  border-color: #313b44;
}
.section.type-1 hr {
  border-color: #313b44;
}
.section.type-1 .form-control {
  background: #384048;
  border-color: transparent !important;
  color: #a5b3bf;
  -o-transition: background-color 0.3s linear;
  -ms-transition: background-color 0.3s linear;
  -moz-transition: background-color 0.3s linear;
  -webkit-transition: background-color 0.3s linear;
  /* ...and now override with proper CSS property */

  transition: background-color 0.3s linear;
}
.section.type-1 .form-control:focus {
  background: #fff;
  -webkit-box-shadow: none;
  -moz-box-shadow: none;
  box-shadow: none;
}
.section.type-2 {
  background: #fff;
}
.section.type-3 {
  background: #f0f2f4;
}
.section.type-4 {
  background: #00a0dc;
}
.section.big {
  height: 100%;
}
.section.splash {
  position: relative;
  z-index: 1;
}
.section.splash h1 {
  font-size: 50px;
  font-weight: 500;
  margin-bottom: 25px;
}
.section-headlines {
  margin-bottom: 60px;
  text-align: center;
}
.section-headlines > h2 {
  font-size: 32px;
}
.section-headlines > h4 {
  font-family: 'Roboto', Arial, sans-serif;
  font-size: 3em;
  text-transform: uppercase;
  color: #00a0dc;
  border-bottom: 2px solid #ddd;
  display: inline-block;
  padding-bottom: 10px;
  margin-bottom: 35px;
  letter-spacing: 2px;
  word-spacing: 5px;
}
.section-headlines > div {
  line-height: 1.8;
}

/*= SPLASH
---------------------------------------------------------------------------------------------- */
.splash-cover {
  background: #363b48;
  width: 100%;
  height: 100%;
  top: 0;
  position: absolute;
  z-index: 2;
  opacity: 0.85;
  filter: alpha(opacity=85);
}
.splash-block {
  position: absolute;
  left: 0;
  top: 0;
  width: 100%;
  height: 100%;
  z-index: 100;
}
.splash-block:before {
  content: '';
  display: inline-block;
  height: 100%;
  vertical-align: middle;
  margin-right: -0.25em;
  /* Adjusts for spacing */

}
.centered {
  display: inline-block;
  vertical-align: middle;
  text-align: center;
  width: 100%;
}

.splash-block p { color:#fff !important; font-size:20px }
/*= JUMPER
---------------------------------------------------------------------------------------------- */
.jumper {
  height: 0;
  position: relative;
  top: -50px;
}
/*= WORK
---------------------------------------------------------------------------------------------- */
.work-thumb {
  display: block;
}
.work-content {
  background: #fff;
  padding: 15px;
}
/*= SERVICES
---------------------------------------------------------------------------------------------- */
.gallery-control {
  margin: 0 0 30px;
  text-align:center;
}
#Grid {
  font-size: 0;
  line-height: 0;
  text-align: justify;
  display: inline-block;
  width: 100%;
}
#Grid .mix {
  opacity: 0;
  display: none;
  width: 20%;
  vertical-align: top;
  font-size: 14px;
}
#Grid .mix > div .media-thumb {
  position: relative;
  overflow: hidden;
}
#Grid .mix > div .media-thumb img {
  display: block;
  max-width: 100%;
}
#Grid .mix > div .media-thumb:hover .media-desc {
  opacity: 1;
  filter: alpha(opacity=100);
}
#Grid .mix > div .media-desc {
  opacity: 0;
  filter: alpha(opacity=0);
  background: #00a0dc  ;
  background: rgba(132,194,37, 0.8);
  color: #fff;
  color: rgba(255, 255, 255, 0.7);
  position: absolute;
  left: 0;
  top: 0;
  width: 100%;
  height: 100%;
  line-height: 20px;
  -o-transition: opacity .3s linear;
  -ms-transition: opacity .3s linear;
  -moz-transition: opacity .3s linear;
  -webkit-transition: opacity .3s linear;
  /* ...and now override with proper CSS property */

  transition: opacity .3s linear;
}
#Grid .mix > div .media-desc > div {
  width: 100%;
  padding: 20px;
  position: absolute;
  bottom: 0;
  left: 0;
}
#Grid .mix > div .media-desc b {
  color: #fff;
  color: rgba(255, 255, 255, 0.9);
  font-size: 16px;
}
#Grid .mix > div .media-detail {
  background: #f9f9f9;
  border-top: 1px solid #eee;
  padding: 10px;
  margin: 0 10px;
  line-height: 20px;
  display: none;
}
@media (max-width: 1020px) {
  #Grid .mix {
    width: 25%;
  }
}
@media (min-width: 768px) and (max-width: 979px) {
  #Grid .mix {
    width: 33.333333%;
  }
}
@media (max-width: 767px) {
  #Grid .mix {
    width: 100%;
  }
}

/*= CLIENTS
---------------------------------------------------------------------------------------------- */
#clients { background:#f7f7f7; padding:40px 0;   border-bottom: 1px solid #E5E5E5;}
#clients .col-lg-2 { text-align:center;}



/*= FEATURES
---------------------------------------------------------------------------------------------- */
.features .media > i {
  font-size: 28px;
  line-height: 55px;
  margin-right: 25px;
  width: 60px;
  height: 60px;
  border: 3px solid #eee;
  -webkit-border-radius: 50%;
  -moz-border-radius: 50%;
  border-radius: 50%;
  text-align: center;
  -webkit-transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
  -moz-transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
  -o-transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
  transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
}
.features .media + .media {
  margin-top: 0;
}
.stats { background:#f7f7f7;}
.stats i {
	  font-size: 28px;
	  line-height: 55px;
	  padding:15px;
	  color:#fff;
	  width: 60px;
	  height: 60px;
	  background:#00a0dc;
	  -webkit-border-radius: 50%;
	  -moz-border-radius: 50%;
	  border-radius: 50%;
	  text-align: center;
	  margin-right:10px;
	  -webkit-transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
	  -moz-transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
	  -o-transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
	  transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
	}

.stats h3{ color:#444; font-size: 25px;}

/*= TEAM
---------------------------------------------------------------------------------------------- */
.team_item {
	margin-bottom:30px;
	text-align:center;
}
.team_body {padding: 25px 15px 31px 15px;
}
.team_item .img_block {margin: 0;
}
.team_item a{ text-decoration:none;}

.team_item .img_block img {
	max-width:100%;
	width:auto;
	margin:auto;
}
.team_body h5 {
	line-height:20px;
	font-size:18px;
	font-weight:400;
	padding:0;
	margin:0 0 11px 0;
	color:#2c2b2b;
	text-transform:uppercase;
}
.team_body h6 {
	line-height:20px;
	font-size:15px;
	font-weight:300;
	padding:0;
	margin:0 0 3px 0;
	color:#2c2b2b;
}

 	
/*= PRICING PLANS
---------------------------------------------------------------------------------------------- */
.pricing-plans .plan-name { text-align:center;}
.pricing-plans .plan-name h2 {
  background: #1e1e1e;
  -webkit-border-radius: 3px 3px 0 0;
  -moz-border-radius: 3px 3px 0 0;
  border-radius: 3px 3px 0 0;
    padding: 50px 25px;
  margin: 0;
  color: #fff;
}

.pricing-plans .plan-featured .plan-name h2 {
  background: #00a0dc;
}

.pricing-plans .plan-price {
  padding: 25px;
  color: #444;
}
.pricing-plans .plan-price > b {
  color: #fff;
  font-size: 60px;
  font-weight: 400;
  letter-spacing: -1px;
}
.pricing-plans .plan-details {
  padding: 0 15px;
  background: #f5f5f5;
}
.pricing-plans .plan-details > div {
  padding: 15px 0;
}
.pricing-plans .plan-details > div + div {
  border-top: 1px solid #eee;
}
.pricing-plans .plan-action {
  background: #f5f5f5;
  border-top: 0;
  -webkit-border-radius: 0 0 3px 3px;
  -moz-border-radius: 0 0 3px 3px;
  border-radius: 0 0 3px 3px;
  padding: 15px;
}
/*= SOCIAL LINKS
---------------------------------------------------------------------------------------------- */
.person .person-avatar {
  margin-right: 20px;
}

.avatar { width:100px;}
/*= SOCIAL LINKS
---------------------------------------------------------------------------------------------- */
.social-links {
  font-size: 30px;
}
.social-links.size-big {
  font-size: 40px;
}
.social-links a {
  color: #aaa;
  text-decoration: none !important;
}
.social-links a:hover {
  color: #00a0dc  ;
}
/*= BRANDS
---------------------------------------------------------------------------------------------- */
.brands .brand {
  border: 1px solid #eee;
  padding: 30px;
  text-align: center;
}
/*= FOOTER
---------------------------------------------------------------------------------------------- */
.footer {
  background: #242b32;
  color: #a5b3bf;
  font-size: 13px;
  padding: 20px 0;
}
.footer * {
  line-height: 20px;
}
.footer .link-social {
  color: inherit;
  opacity: 0.8;
  filter: alpha(opacity=80);
  margin-left: 15px;
  text-decoration: none !important;
  font-size: 18px;
}
.footer .link-social:hover {
  opacity: 1;
  filter: alpha(opacity=100);
}
.section-contact .address-row {
  display: table;
  width: 100%;
}
.section-contact .address-sign {
  display: table-cell;
  width: 30px;
  opacity: 0.3;
  filter: alpha(opacity=30);
}
.section-contact .address-info {
  display: table-cell;
}

/*= EMAIL SUBSCRIPTION---------------------------------------------------------------------------------------------- */

.email-susbscription input[type="email"] {width: 91%;
  max-width: 600px;
  height: 56px;
  padding: 0 4%;
  background-: #fff;
  border:1px solid #fff;
  -moz-border-radius: 5px;
  -webkit-border-radius: 5px;
  border-radius: 5px;
  font-size: 16px;
  margin: 0 10px 0 0;

}
.email-susbscription h1 { color:#fff;}
.email-susbscription p{ color:#fff; margin-bottom:30px; }
.email-susbscription .btn {
	  padding: 17px;
	  }
/*= BOOTSTRAP OVERWRITE: ACCORDIANS
---------------------------------------------------------------------------------------------- */
.panel-group .panel {
  -webkit-border-radius: 0;
  -moz-border-radius: 0;
  border-radius: 0;
  border: 0;
  -webkit-box-shadow: none;
  -moz-box-shadow: none;
  box-shadow: none;
}
.panel-group .panel + .panel {
  border-top: 1px solid #eee;
  margin-top: 0;
  padding-top: 10px;
}
.panel-group .panel-heading {
  padding: 0 0 10px;
}
.panel-group .panel-body {
  padding: 5px 0 15px;
  border-top: 0 !important;
}
.panel-title {
  font-size: 18px;
}
.panel-title a {
  display: block;
  overflow: hidden;
  position: relative;
  text-decoration: none !important;
}
.panel-title a i {
  color: #bbb;
  font-size: 14px;
  height: 23px;
  line-height: 23px;
  float: left;
  margin-right: 10px;
  width: 20px;
  text-align: center;
}
.panel-title a .icon-minus {
  display: none;
}
.panel-title a.collapsed .icon-minus {
  display: block;
}
.panel-title a.collapsed .icon-plus {
  display: none;
}
/*= TESTIMONIAL
---------------------------------------------------------------------------------------------- */
#carousel-testimonial {
  margin-top: 50px;
}
.testimonial {
  background: #f9f9f9;
  padding: 40px;
}
.testimonial-avatar {
  padding-left: 30px;
}
.testimonial-avatar img {
  width: 100px;
  height: auto;
}
.testimonial-content .lead {
  border-left: 1px solid #ddd;
  padding-left: 30px;
  font-size: 18px;
  margin-top: 10px;
}
.carousel-controller {
  position: absolute;
  right: 15px;
  top: 15px;
}
.dis-table {
  display: table;
  width: 100%;
}
.dis-tablecell {
  display: table-cell;
  vertical-align: top;
}
@media (max-width: 767px) {
  .section.splash h1 {
    font-size: 40px;
  }
  .person-avatar img {
    width: 80px;
  }
}
@media (min-width: 768px) and (max-width: 979px) {
  /*= RESPONSIVE RESET
  ---------------------------------------------------------------------------------------------- */
}
@media (max-width: 979px) {
  /*= RESPONSIVE RESET
  ---------------------------------------------------------------------------------------------- */
}

#success{
	width: 100%;
	padding: 10px;
	text-align: center;
	color: green;
	display:none;
}
#error{
	width: 100%;
	padding: 10px;
	text-align: center;
	color: red;
	display:none;
})***", 19388));
        res.end();
    });


std::string HACK_SOURCECODE_0(R"NS0**NS1**(// MIT License
// 
// Copyright (c) 2018 Tiger
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


// Copyright (c) 2014, ipkn
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
// 
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
// 
// * Neither the name of the author nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <boost/optional.hpp>
#include <sys/types.h>
#include <stdint.h>
#include <assert.h>
#include <stddef.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/functional/hash.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <boost/asio.hpp>
#include <algorithm>
#include <memory>
#include <boost/lexical_cast.hpp>
#include <boost/operators.hpp>
#include <fstream>
#include <iterator>
#include <functional>
#include <ctime>
#include <sstream>
#include <deque>
#include <chrono>
#include <thread>
#include <cstdint>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <boost/array.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <utility>
#include <atomic>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <future>
#include <condition_variable>






       

       









namespace crow
{





int qs_strncmp(const char * s, const char * qs, size_t n);






int qs_parse(char * qs, char * qs_kv[], int qs_kv_size);



int qs_decode(char * qs);






 char * qs_k2v(const char * key, char * const * qs_kv, int qs_kv_size, int nth);




char * qs_scanvalue(const char * key, const char * qs, char * val, size_t val_len);

inline int qs_strncmp(const char * s, const char * qs, size_t n)
{
    int i=0;
    unsigned char u1, u2, unyb, lnyb;

    while(n-- > 0)
    {
        u1 = (unsigned char) *s++;
        u2 = (unsigned char) *qs++;

        if ( ! ((((u1)=='=')||((u1)=='#')||((u1)=='&')||((u1)=='\0')) ? 0 : 1) ) { u1 = '\0'; }
        if ( ! ((((u2)=='=')||((u2)=='#')||((u2)=='&')||((u2)=='\0')) ? 0 : 1) ) { u2 = '\0'; }

        if ( u1 == '+' ) { u1 = ' '; }
        if ( u1 == '%' )
        {
            unyb = (unsigned char) *s++;
            lnyb = (unsigned char) *s++;
            if ( ((((unyb)>='0'&&(unyb)<='9') || ((unyb)>='A'&&(unyb)<='F') || ((unyb)>='a'&&(unyb)<='f')) ? 1 : 0) && ((((lnyb)>='0'&&(lnyb)<='9') || ((lnyb)>='A'&&(lnyb)<='F') || ((lnyb)>='a'&&(lnyb)<='f')) ? 1 : 0) )
                u1 = ((((unyb)>='0'&&(unyb)<='9') ? (unyb)-48 : ((unyb)>='A'&&(unyb)<='F') ? (unyb)-55 : ((unyb)>='a'&&(unyb)<='f') ? (unyb)-87 : 0) * 16) + (((lnyb)>='0'&&(lnyb)<='9') ? (lnyb)-48 : ((lnyb)>='A'&&(lnyb)<='F') ? (lnyb)-55 : ((lnyb)>='a'&&(lnyb)<='f') ? (lnyb)-87 : 0);
            else
                u1 = '\0';
        }

        if ( u2 == '+' ) { u2 = ' '; }
        if ( u2 == '%' )
        {
            unyb = (unsigned char) *qs++;
            lnyb = (unsigned char) *qs++;
            if ( ((((unyb)>='0'&&(unyb)<='9') || ((unyb)>='A'&&(unyb)<='F') || ((unyb)>='a'&&(unyb)<='f')) ? 1 : 0) && ((((lnyb)>='0'&&(lnyb)<='9') || ((lnyb)>='A'&&(lnyb)<='F') || ((lnyb)>='a'&&(lnyb)<='f')) ? 1 : 0) )
                u2 = ((((unyb)>='0'&&(unyb)<='9') ? (unyb)-48 : ((unyb)>='A'&&(unyb)<='F') ? (unyb)-55 : ((unyb)>='a'&&(unyb)<='f') ? (unyb)-87 : 0) * 16) + (((lnyb)>='0'&&(lnyb)<='9') ? (lnyb)-48 : ((lnyb)>='A'&&(lnyb)<='F') ? (lnyb)-55 : ((lnyb)>='a'&&(lnyb)<='f') ? (lnyb)-87 : 0);
            else
                u2 = '\0';
        }

        if ( u1 != u2 )
            return u1 - u2;
        if ( u1 == '\0' )
            return 0;
        i++;
    }
    if ( ((((*qs)=='=')||((*qs)=='#')||((*qs)=='&')||((*qs)=='\0')) ? 0 : 1) )
        return -1;
    else
        return 0;
}


inline int qs_parse(char * qs, char * qs_kv[], int qs_kv_size)
{
    int i, j;
    char * substr_ptr;

    for(i=0; i<qs_kv_size; i++) qs_kv[i] = NULL;


    substr_ptr = qs + strcspn(qs, "?#");
    if (substr_ptr[0] != '\0')
        substr_ptr++;
    else
        return 0;

    i=0;
    while(i<qs_kv_size)
    {
        qs_kv[i] = substr_ptr;
        j = strcspn(substr_ptr, "&");
        if ( substr_ptr[j] == '\0' ) { break; }
        substr_ptr += j + 1;
        i++;
    }
    i++;



    for(j=0; j<i; j++)
    {
        substr_ptr = qs_kv[j] + strcspn(qs_kv[j], "=&#");
        if ( substr_ptr[0] == '&' || substr_ptr[0] == '\0')
            substr_ptr[0] = '\0';
        else
            qs_decode(++substr_ptr);
    }





    return i;
}


inline int qs_decode(char * qs)
{
    int i=0, j=0;

    while( ((((qs[j])=='=')||((qs[j])=='#')||((qs[j])=='&')||((qs[j])=='\0')) ? 0 : 1) )
    {
        if ( qs[j] == '+' ) { qs[i] = ' '; }
        else if ( qs[j] == '%' )
        {
            if ( ! ((((qs[j+1])>='0'&&(qs[j+1])<='9') || ((qs[j+1])>='A'&&(qs[j+1])<='F') || ((qs[j+1])>='a'&&(qs[j+1])<='f')) ? 1 : 0) || ! ((((qs[j+2])>='0'&&(qs[j+2])<='9') || ((qs[j+2])>='A'&&(qs[j+2])<='F') || ((qs[j+2])>='a'&&(qs[j+2])<='f')) ? 1 : 0) )
            {
                qs[i] = '\0';
                return i;
            }
            qs[i] = ((((qs[j+1])>='0'&&(qs[j+1])<='9') ? (qs[j+1])-48 : ((qs[j+1])>='A'&&(qs[j+1])<='F') ? (qs[j+1])-55 : ((qs[j+1])>='a'&&(qs[j+1])<='f') ? (qs[j+1])-87 : 0) * 16) + (((qs[j+2])>='0'&&(qs[j+2])<='9') ? (qs[j+2])-48 : ((qs[j+2])>='A'&&(qs[j+2])<='F') ? (qs[j+2])-55 : ((qs[j+2])>='a'&&(qs[j+2])<='f') ? (qs[j+2])-87 : 0);
            j+=2;
        }
        else
        {
            qs[i] = qs[j];
        }
        i++; j++;
    }
    qs[i] = '\0';

    return i;
}


inline char * qs_k2v(const char * key, char * const * qs_kv, int qs_kv_size, int nth = 0)
{
    int i;
    size_t key_len, skip;

    key_len = strlen(key);




    for(i=0; i<qs_kv_size; i++)
    {

        if ( qs_strncmp(key, qs_kv[i], key_len) == 0 )
        {
            skip = strcspn(qs_kv[i], "=");
            if ( qs_kv[i][skip] == '=' )
                skip++;

            if(nth == 0)
                return qs_kv[i] + skip;
            else
                --nth;
        }
    }


    return NULL;
}

inline boost::optional<std::pair<std::string, std::string>> qs_dict_name2kv(const char * dict_name, char * const * qs_kv, int qs_kv_size, int nth = 0)
{
    int i;
    size_t name_len, skip_to_eq, skip_to_brace_open, skip_to_brace_close;

    name_len = strlen(dict_name);




    for(i=0; i<qs_kv_size; i++)
    {
        if ( strncmp(dict_name, qs_kv[i], name_len) == 0 )
        {
            skip_to_eq = strcspn(qs_kv[i], "=");
            if ( qs_kv[i][skip_to_eq] == '=' )
                skip_to_eq++;
            skip_to_brace_open = strcspn(qs_kv[i], "[");
            if ( qs_kv[i][skip_to_brace_open] == '[' )
                skip_to_brace_open++;
            skip_to_brace_close = strcspn(qs_kv[i], "]");

            if ( skip_to_brace_open <= skip_to_brace_close &&
                 skip_to_brace_open > 0 &&
                 skip_to_brace_close > 0 &&
                 nth == 0 )
            {
                auto key = std::string(qs_kv[i] + skip_to_brace_open, skip_to_brace_close - skip_to_brace_open);
                auto value = std::string(qs_kv[i] + skip_to_eq);
                return boost::make_optional(std::make_pair(key, value));
            }
            else
            {
                --nth;
            }
        }
    }


    return boost::none;
}


inline char * qs_scanvalue(const char * key, const char * qs, char * val, size_t val_len)
{
    size_t i, key_len;
    const char * tmp;


    if ( (tmp = strchr(qs, '?')) != NULL )
        qs = tmp + 1;

    key_len = strlen(key);
    while(qs[0] != '#' && qs[0] != '\0')
    {
        if ( qs_strncmp(key, qs, key_len) == 0 )
            break;
        qs += strcspn(qs, "&") + 1;
    }

    if ( qs[0] == '\0' ) return NULL;

    qs += strcspn(qs, "=&#");
    if ( qs[0] == '=' )
    {
        qs++;
        i = strcspn(qs, "&=#");



        strncpy(val, qs, (val_len - 1)<(i + 1) ? (val_len - 1) : (i + 1));

  qs_decode(val);
    }
    else
    {
        if ( val_len > 0 )
            val[0] = '\0';
    }

    return val;
}
}



namespace crow
{
    class query_string
    {
    public:
        static const int MAX_KEY_VALUE_PAIRS_COUNT = 256;

        query_string()
        {

        }

        query_string(const query_string& qs)
            : url_(qs.url_)
        {
            for(auto p:qs.key_value_pairs_)
            {
                key_value_pairs_.push_back((char*)(p-qs.url_.c_str()+url_.c_str()));
            }
        }

        query_string& operator = (const query_string& qs)
        {
            url_ = qs.url_;
            key_value_pairs_.clear();
            for(auto p:qs.key_value_pairs_)
            {
                key_value_pairs_.push_back((char*)(p-qs.url_.c_str()+url_.c_str()));
            }
            return *this;
        }

        query_string& operator = (query_string&& qs)
        {
            key_value_pairs_ = std::move(qs.key_value_pairs_);
            char* old_data = (char*)qs.url_.c_str();
            url_ = std::move(qs.url_);
            for(auto& p:key_value_pairs_)
            {
                p += (char*)url_.c_str() - old_data;
            }
            return *this;
        }


        query_string(std::string url)
            : url_(std::move(url))
        {
            if (url_.empty())
                return;

            key_value_pairs_.resize(MAX_KEY_VALUE_PAIRS_COUNT);

            int count = qs_parse(&url_[0], &key_value_pairs_[0], MAX_KEY_VALUE_PAIRS_COUNT);
            key_value_pairs_.resize(count);
        }

        void clear()
        {
            key_value_pairs_.clear();
            url_.clear();
        }

        friend std::ostream& operator<<(std::ostream& os, const query_string& qs)
        {
            os << "[ ";
            for(size_t i = 0; i < qs.key_value_pairs_.size(); ++i) {
                if (i)
                    os << ", ";
                os << qs.key_value_pairs_[i];
            }
            os << " ]";
            return os;

        }

        char* get (const std::string& name) const
        {
            char* ret = qs_k2v(name.c_str(), key_value_pairs_.data(), key_value_pairs_.size());
            return ret;
        }

        std::vector<char*> get_list (const std::string& name) const
        {
            std::vector<char*> ret;
            std::string plus = name + "[]";
            char* element = nullptr;

            int count = 0;
            while(1)
            {
                element = qs_k2v(plus.c_str(), key_value_pairs_.data(), key_value_pairs_.size(), count++);
                if (!element)
                    break;
                ret.push_back(element);
            }
            return ret;
        }

        std::unordered_map<std::string, std::string> get_dict (const std::string& name) const
        {
            std::unordered_map<std::string, std::string> ret;

            int count = 0;
            while(1)
            {
                if (auto element = qs_dict_name2kv(name.c_str(), key_value_pairs_.data(), key_value_pairs_.size(), count++))
                    ret.insert(*element);
                else
                    break;
            }
            return ret;
        }

    private:
        std::string url_;
        std::vector<char*> key_value_pairs_;
    };

}



extern "C" {











typedef struct http_parser http_parser;
typedef struct http_parser_settings http_parser_settings;

typedef int (*http_data_cb) (http_parser*, const char *at, size_t length);
typedef int (*http_cb) (http_parser*);

enum http_method
  {

  HTTP_DELETE = 0, HTTP_GET = 1, HTTP_HEAD = 2, HTTP_POST = 3, HTTP_PUT = 4, HTTP_CONNECT = 5, HTTP_OPTIONS = 6, HTTP_TRACE = 7, HTTP_PATCH = 8, HTTP_PURGE = 9, HTTP_COPY = 10, HTTP_LOCK = 11, HTTP_MKCOL = 12, HTTP_MOVE = 13, HTTP_PROPFIND = 14, HTTP_PROPPATCH = 15, HTTP_SEARCH = 16, HTTP_UNLOCK = 17, HTTP_REPORT = 18, HTTP_MKACTIVITY = 19, HTTP_CHECKOUT = 20, HTTP_MERGE = 21, HTTP_MSEARCH = 22, HTTP_NOTIFY = 23, HTTP_SUBSCRIBE = 24, HTTP_UNSUBSCRIBE = 25, HTTP_MKCALENDAR = 26,

  };


enum http_parser_type { HTTP_REQUEST, HTTP_RESPONSE, HTTP_BOTH };



enum flags
  { F_CHUNKED = 1 << 0
  , F_CONNECTION_KEEP_ALIVE = 1 << 1
  , F_CONNECTION_CLOSE = 1 << 2
  , F_TRAILING = 1 << 3
  , F_UPGRADE = 1 << 4
  , F_SKIPBODY = 1 << 5
  };

enum http_errno {
  HPE_OK, HPE_CB_message_begin, HPE_CB_url, HPE_CB_header_field, HPE_CB_header_value, HPE_CB_headers_complete, HPE_CB_body, HPE_CB_message_complete, HPE_CB_status, HPE_INVALID_EOF_STATE, HPE_HEADER_OVERFLOW, HPE_CLOSED_CONNECTION, HPE_INVALID_VERSION, HPE_INVALID_STATUS, HPE_INVALID_METHOD, HPE_INVALID_URL, HPE_INVALID_HOST, HPE_INVALID_PORT, HPE_INVALID_PATH, HPE_INVALID_QUERY_STRING, HPE_INVALID_FRAGMENT, HPE_LF_EXPECTED, HPE_INVALID_HEADER_TOKEN, HPE_INVALID_CONTENT_LENGTH, HPE_INVALID_CHUNK_SIZE, HPE_INVALID_CONSTANT, HPE_INVALID_INTERNAL_STATE, HPE_STRICT, HPE_PAUSED, HPE_UNKNOWN,
};







struct http_parser {

  unsigned int type : 2;
  unsigned int flags : 6;
  unsigned int state : 8;
  unsigned int header_state : 8;
  unsigned int index : 8;

  uint32_t nread;
  uint64_t content_length;


  unsigned short http_major;
  unsigned short http_minor;
  unsigned int status_code : 16;
  unsigned int method : 8;
  unsigned int http_errno : 7;






  unsigned int upgrade : 1;


  void *data;
};


struct http_parser_settings {
  http_cb on_message_begin;
  http_data_cb on_url;
  http_data_cb on_status;
  http_data_cb on_header_field;
  http_data_cb on_header_value;
  http_cb on_headers_complete;
  http_data_cb on_body;
  http_cb on_message_complete;
};


enum http_parser_url_fields
  { UF_SCHEMA = 0
  , UF_HOST = 1
  , UF_PORT = 2
  , UF_PATH = 3
  , UF_QUERY = 4
  , UF_FRAGMENT = 5
  , UF_USERINFO = 6
  , UF_MAX = 7
  };

struct http_parser_url {
  uint16_t field_set;
  uint16_t port;

  struct {
    uint16_t off;
    uint16_t len;
  } field_data[UF_MAX];
};

unsigned long http_parser_version(void);

void http_parser_init(http_parser *parser, enum http_parser_type type);


size_t http_parser_execute(http_parser *parser,
                           const http_parser_settings *settings,
                           const char *data,
                           size_t len);

int http_should_keep_alive(const http_parser *parser);


const char *http_method_str(enum http_method m);


const char *http_errno_name(enum http_errno err);


const char *http_errno_description(enum http_errno err);


int http_parser_parse_url(const char *buf, size_t buflen,
                          int is_connect,
                          struct http_parser_url *u);


void http_parser_pause(http_parser *parser, int paused);


int http_body_is_final(const http_parser *parser);








enum state
  { s_dead = 1

  , s_start_req_or_res
  , s_res_or_resp_H
  , s_start_res
  , s_res_H
  , s_res_HT
  , s_res_HTT
  , s_res_HTTP
  , s_res_first_http_major
  , s_res_http_major
  , s_res_first_http_minor
  , s_res_http_minor
  , s_res_first_status_code
  , s_res_status_code
  , s_res_status_start
  , s_res_status
  , s_res_line_almost_done

  , s_start_req

  , s_req_method
  , s_req_spaces_before_url
  , s_req_schema
  , s_req_schema_slash
  , s_req_schema_slash_slash
  , s_req_server_start
  , s_req_server
  , s_req_server_with_at
  , s_req_path
  , s_req_query_string_start
  , s_req_query_string
  , s_req_fragment_start
  , s_req_fragment
  , s_req_http_start
  , s_req_http_H
  , s_req_http_HT
  , s_req_http_HTT
  , s_req_http_HTTP
  , s_req_first_http_major
  , s_req_http_major
  , s_req_first_http_minor
  , s_req_http_minor
  , s_req_line_almost_done

  , s_header_field_start
  , s_header_field
  , s_header_value_discard_ws
  , s_header_value_discard_ws_almost_done
  , s_header_value_discard_lws
  , s_header_value_start
  , s_header_value
  , s_header_value_lws

  , s_header_almost_done

  , s_chunk_size_start
  , s_chunk_size
  , s_chunk_parameters
  , s_chunk_size_almost_done

  , s_headers_almost_done
  , s_headers_done






  , s_chunk_data
  , s_chunk_data_almost_done
  , s_chunk_data_done

  , s_body_identity
  , s_body_identity_eof

  , s_message_done
  };





enum header_states
  { h_general = 0
  , h_C
  , h_CO
  , h_CON

  , h_matching_connection
  , h_matching_proxy_connection
  , h_matching_content_length
  , h_matching_transfer_encoding
  , h_matching_upgrade

  , h_connection
  , h_content_length
  , h_transfer_encoding
  , h_upgrade

  , h_matching_transfer_encoding_chunked
  , h_matching_connection_keep_alive
  , h_matching_connection_close

  , h_transfer_encoding_chunked
  , h_connection_keep_alive
  , h_connection_close
  };

enum http_host_state
  {
    s_http_host_dead = 1
  , s_http_userinfo_start
  , s_http_userinfo
  , s_http_host_start
  , s_http_host_v6_start
  , s_http_host
  , s_http_host_v6
  , s_http_host_v6_end
  , s_http_host_port_start
  , s_http_host_port
};

int http_message_needs_eof(const http_parser *parser);

inline enum state
parse_url_char(enum state s, const char ch)
{







static const uint8_t normal_url_char[32] = {

        0 | 0 | 0 | 0 | 0 | 0 | 0 | 0,

        0 | 0 | 0 | 0 | 0 | 0 | 0 | 0,

        0 | 0 | 0 | 0 | 0 | 0 | 0 | 0,

        0 | 0 | 0 | 0 | 0 | 0 | 0 | 0,

        0 | 2 | 4 | 0 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 0,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 128,

        1 | 2 | 4 | 8 | 16 | 32 | 64 | 0, };



  if (ch == ' ' || ch == '\r' || ch == '\n') {
    return s_dead;
  }


  if (ch == '\t' || ch == '\f') {
    return s_dead;
  }


  switch (s) {
    case s_req_spaces_before_url:




      if (ch == '/' || ch == '*') {
        return s_req_path;
      }

      if (((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z')) {
        return s_req_schema;
      }

      break;

    case s_req_schema:
      if (((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z')) {
        return s;
      }

      if (ch == ':') {
        return s_req_schema_slash;
      }

      break;

    case s_req_schema_slash:
      if (ch == '/') {
        return s_req_schema_slash_slash;
      }

      break;

    case s_req_schema_slash_slash:
      if (ch == '/') {
        return s_req_server_start;
      }

      break;

    case s_req_server_with_at:
      if (ch == '@') {
        return s_dead;
      }


    case s_req_server_start:
    case s_req_server:
      if (ch == '/') {
        return s_req_path;
      }

      if (ch == '?') {
        return s_req_query_string_start;
      }

      if (ch == '@') {
        return s_req_server_with_at;
      }

      if (((((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z') || ((ch) >= '0' && (ch) <= '9')) || ((ch) == '-' || (ch) == '_' || (ch) == '.' || (ch) == '!' || (ch) == '~' || (ch) == '*' || (ch) == '\'' || (ch) == '(' || (ch) == ')') || (ch) == '%' || (ch) == ';' || (ch) == ':' || (ch) == '&' || (ch) == '=' || (ch) == '+' || (ch) == '$' || (ch) == ',') || ch == '[' || ch == ']') {
        return s_req_server;
      }

      break;

    case s_req_path:
      if (((!!((unsigned int) (normal_url_char)[(unsigned int) ((unsigned char)ch) >> 3] & (1 << ((unsigned int) ((unsigned char)ch) & 7)))))) {
        return s;
      }

      switch (ch) {
        case '?':
          return s_req_query_string_start;

        case '#':
          return s_req_fragment_start;
      }

      break;

    case s_req_query_string_start:
    case s_req_query_string:
      if (((!!((unsigned int) (normal_url_char)[(unsigned int) ((unsigned char)ch) >> 3] & (1 << ((unsigned int) ((unsigned char)ch) & 7)))))) {
        return s_req_query_string;
      }

      switch (ch) {
        case '?':

          return s_req_query_string;

        case '#':
          return s_req_fragment_start;
      }

      break;

    case s_req_fragment_start:
      if (((!!((unsigned int) (normal_url_char)[(unsigned int) ((unsigned char)ch) >> 3] & (1 << ((unsigned int) ((unsigned char)ch) & 7)))))) {
        return s_req_fragment;
      }

      switch (ch) {
        case '?':
          return s_req_fragment;

        case '#':
          return s;
      }

      break;

    case s_req_fragment:
      if (((!!((unsigned int) (normal_url_char)[(unsigned int) ((unsigned char)ch) >> 3] & (1 << ((unsigned int) ((unsigned char)ch) & 7)))))) {
        return s;
      }

      switch (ch) {
        case '?':
        case '#':
          return s;
      }

      break;

    default:
      break;
  }


  return s_dead;
}

inline size_t http_parser_execute (http_parser *parser,
                            const http_parser_settings *settings,
                            const char *data,
                            size_t len)
{
static const char *method_strings[] =
  {

  "DELETE", "GET", "HEAD", "POST", "PUT", "CONNECT", "OPTIONS", "TRACE", "PATCH", "PURGE", "COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND", "PROPPATCH", "SEARCH", "UNLOCK", "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE", "M-SEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "MKCALENDAR",

  };

static const char tokens[256] = {

        0, 0, 0, 0, 0, 0, 0, 0,

        0, 0, 0, 0, 0, 0, 0, 0,

        0, 0, 0, 0, 0, 0, 0, 0,

        0, 0, 0, 0, 0, 0, 0, 0,

        0, '!', 0, '#', '$', '%', '&', '\'',

        0, 0, '*', '+', 0, '-', '.', 0,

       '0', '1', '2', '3', '4', '5', '6', '7',

       '8', '9', 0, 0, 0, 0, 0, 0,

        0, 'a', 'b', 'c', 'd', 'e', 'f', 'g',

       'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',

       'p', 'q', 'r', 's', 't', 'u', 'v', 'w',

       'x', 'y', 'z', 0, 0, 0, '^', '_',

       '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g',

       'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',

       'p', 'q', 'r', 's', 't', 'u', 'v', 'w',

       'x', 'y', 'z', 0, '|', 0, '~', 0 };


static const int8_t unhex[256] =
  {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  , 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1
  ,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  };



  char c, ch;
  int8_t unhex_val;
  const char *p = data;
  const char *header_field_mark = 0;
  const char *header_value_mark = 0;
  const char *url_mark = 0;
  const char *body_mark = 0;
  const char *status_mark = 0;


  if (((enum http_errno) (parser)->http_errno) != HPE_OK) {
    return 0;
  }

  if (len == 0) {
    switch (parser->state) {
      case s_body_identity_eof:



        do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } } while (0);
        return 0;

      case s_dead:
      case s_start_req_or_res:
      case s_start_res:
      case s_start_req:
        return 0;

      default:
        do { parser->http_errno = (HPE_INVALID_EOF_STATE); } while(0);
        return 1;
    }
  }


  if (parser->state == s_header_field)
    header_field_mark = data;
  if (parser->state == s_header_value)
    header_value_mark = data;
  switch (parser->state) {
  case s_req_path:
  case s_req_schema:
  case s_req_schema_slash:
  case s_req_schema_slash_slash:
  case s_req_server_start:
  case s_req_server:
  case s_req_server_with_at:
  case s_req_query_string_start:
  case s_req_query_string:
  case s_req_fragment_start:
  case s_req_fragment:
    url_mark = data;
    break;
  case s_res_status:
    status_mark = data;
    break;
  }

  for (p=data; p != data + len; p++) {
    ch = *p;

    if ((parser->state <= s_headers_done)) {
      ++parser->nread;

      if (parser->nread > ((80*1024))) {
        do { parser->http_errno = (HPE_HEADER_OVERFLOW); } while(0);
        goto error;
      }
    }

    reexecute_byte:
    switch (parser->state) {

      case s_dead:



        if (ch == '\r' || ch == '\n')
          break;

        do { parser->http_errno = (HPE_CLOSED_CONNECTION); } while(0);
        goto error;

      case s_start_req_or_res:
      {
        if (ch == '\r' || ch == '\n')
          break;
        parser->flags = 0;
        parser->content_length = ((uint64_t) -1);

        if (ch == 'H') {
          parser->state = s_res_or_resp_H;

          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_begin) { if (0 != settings->on_message_begin(parser)) { do { parser->http_errno = (HPE_CB_message_begin); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
        } else {
          parser->type = HTTP_REQUEST;
          parser->state = s_start_req;
          goto reexecute_byte;
        }

        break;
      }

      case s_res_or_resp_H:
        if (ch == 'T') {
          parser->type = HTTP_RESPONSE;
          parser->state = s_res_HT;
        } else {
          if (ch != 'E') {
            do { parser->http_errno = (HPE_INVALID_CONSTANT); } while(0);
            goto error;
          }

          parser->type = HTTP_REQUEST;
          parser->method = HTTP_HEAD;
          parser->index = 2;
          parser->state = s_req_method;
        }
        break;

      case s_start_res:
      {
        parser->flags = 0;
        parser->content_length = ((uint64_t) -1);

        switch (ch) {
          case 'H':
            parser->state = s_res_H;
            break;

          case '\r':
          case '\n':
            break;

          default:
            do { parser->http_errno = (HPE_INVALID_CONSTANT); } while(0);
            goto error;
        }

        do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_begin) { if (0 != settings->on_message_begin(parser)) { do { parser->http_errno = (HPE_CB_message_begin); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
        break;
      }

      case s_res_H:
        do { if (ch != 'T') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_res_HT;
        break;

      case s_res_HT:
        do { if (ch != 'T') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_res_HTT;
        break;

      case s_res_HTT:
        do { if (ch != 'P') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_res_HTTP;
        break;

      case s_res_HTTP:
        do { if (ch != '/') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_res_first_http_major;
        break;

      case s_res_first_http_major:
        if (ch < '0' || ch > '9') {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_major = ch - '0';
        parser->state = s_res_http_major;
        break;


      case s_res_http_major:
      {
        if (ch == '.') {
          parser->state = s_res_first_http_minor;
          break;
        }

        if (!((ch) >= '0' && (ch) <= '9')) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_major *= 10;
        parser->http_major += ch - '0';

        if (parser->http_major > 999) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        break;
      }


      case s_res_first_http_minor:
        if (!((ch) >= '0' && (ch) <= '9')) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_minor = ch - '0';
        parser->state = s_res_http_minor;
        break;


      case s_res_http_minor:
      {
        if (ch == ' ') {
          parser->state = s_res_first_status_code;
          break;
        }

        if (!((ch) >= '0' && (ch) <= '9')) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_minor *= 10;
        parser->http_minor += ch - '0';

        if (parser->http_minor > 999) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        break;
      }

      case s_res_first_status_code:
      {
        if (!((ch) >= '0' && (ch) <= '9')) {
          if (ch == ' ') {
            break;
          }

          do { parser->http_errno = (HPE_INVALID_STATUS); } while(0);
          goto error;
        }
        parser->status_code = ch - '0';
        parser->state = s_res_status_code;
        break;
      }

      case s_res_status_code:
      {
        if (!((ch) >= '0' && (ch) <= '9')) {
          switch (ch) {
            case ' ':
              parser->state = s_res_status_start;
              break;
            case '\r':
              parser->state = s_res_line_almost_done;
              break;
            case '\n':
              parser->state = s_header_field_start;
              break;
            default:
              do { parser->http_errno = (HPE_INVALID_STATUS); } while(0);
              goto error;
          }
          break;
        }

        parser->status_code *= 10;
        parser->status_code += ch - '0';

        if (parser->status_code > 999) {
          do { parser->http_errno = (HPE_INVALID_STATUS); } while(0);
          goto error;
        }

        break;
      }

      case s_res_status_start:
      {
        if (ch == '\r') {
          parser->state = s_res_line_almost_done;
          break;
        }

        if (ch == '\n') {
          parser->state = s_header_field_start;
          break;
        }

        do { if (!status_mark) { status_mark = p; } } while (0);
        parser->state = s_res_status;
        parser->index = 0;
        break;
      }

      case s_res_status:
        if (ch == '\r') {
          parser->state = s_res_line_almost_done;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (status_mark) { if (settings->on_status) { if (0 != settings->on_status(parser, status_mark, (p - status_mark))) { do { parser->http_errno = (HPE_CB_status); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } status_mark = NULL; } } while (0);
          break;
        }

        if (ch == '\n') {
          parser->state = s_header_field_start;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (status_mark) { if (settings->on_status) { if (0 != settings->on_status(parser, status_mark, (p - status_mark))) { do { parser->http_errno = (HPE_CB_status); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } status_mark = NULL; } } while (0);
          break;
        }

        break;

      case s_res_line_almost_done:
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_header_field_start;
        break;

      case s_start_req:
      {
        if (ch == '\r' || ch == '\n')
          break;
        parser->flags = 0;
        parser->content_length = ((uint64_t) -1);

        if (!((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z')) {
          do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
          goto error;
        }

        parser->method = (enum http_method) 0;
        parser->index = 1;
        switch (ch) {
          case 'C': parser->method = HTTP_CONNECT; break;
          case 'D': parser->method = HTTP_DELETE; break;
          case 'G': parser->method = HTTP_GET; break;
          case 'H': parser->method = HTTP_HEAD; break;
          case 'L': parser->method = HTTP_LOCK; break;
          case 'M': parser->method = HTTP_MKCOL; break;
          case 'N': parser->method = HTTP_NOTIFY; break;
          case 'O': parser->method = HTTP_OPTIONS; break;
          case 'P': parser->method = HTTP_POST;

            break;
          case 'R': parser->method = HTTP_REPORT; break;
          case 'S': parser->method = HTTP_SUBSCRIBE; break;
          case 'T': parser->method = HTTP_TRACE; break;
          case 'U': parser->method = HTTP_UNLOCK; break;
          default:
            do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
            goto error;
        }
        parser->state = s_req_method;

        do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_begin) { if (0 != settings->on_message_begin(parser)) { do { parser->http_errno = (HPE_CB_message_begin); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);

        break;
      }

      case s_req_method:
      {
        const char *matcher;
        if (ch == '\0') {
          do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
          goto error;
        }

        matcher = method_strings[parser->method];
        if (ch == ' ' && matcher[parser->index] == '\0') {
          parser->state = s_req_spaces_before_url;
        } else if (ch == matcher[parser->index]) {
          ;
        } else if (parser->method == HTTP_CONNECT) {
          if (parser->index == 1 && ch == 'H') {
            parser->method = HTTP_CHECKOUT;
          } else if (parser->index == 2 && ch == 'P') {
            parser->method = HTTP_COPY;
          } else {
            do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
            goto error;
          }
        } else if (parser->method == HTTP_MKCOL) {
          if (parser->index == 1 && ch == 'O') {
            parser->method = HTTP_MOVE;
          } else if (parser->index == 1 && ch == 'E') {
            parser->method = HTTP_MERGE;
          } else if (parser->index == 1 && ch == '-') {
            parser->method = HTTP_MSEARCH;
          } else if (parser->index == 2 && ch == 'A') {
            parser->method = HTTP_MKACTIVITY;
          } else if (parser->index == 3 && ch == 'A') {
            parser->method = HTTP_MKCALENDAR;
          } else {
            do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
            goto error;
          }
        } else if (parser->method == HTTP_SUBSCRIBE) {
          if (parser->index == 1 && ch == 'E') {
            parser->method = HTTP_SEARCH;
          } else {
            do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
            goto error;
          }
        } else if (parser->index == 1 && parser->method == HTTP_POST) {
          if (ch == 'R') {
            parser->method = HTTP_PROPFIND;
          } else if (ch == 'U') {
            parser->method = HTTP_PUT;
          } else if (ch == 'A') {
            parser->method = HTTP_PATCH;
          } else {
            do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
            goto error;
          }
        } else if (parser->index == 2) {
          if (parser->method == HTTP_PUT) {
            if (ch == 'R') {
              parser->method = HTTP_PURGE;
            } else {
              do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
              goto error;
            }
          } else if (parser->method == HTTP_UNLOCK) {
            if (ch == 'S') {
              parser->method = HTTP_UNSUBSCRIBE;
            } else {
              do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
              goto error;
            }
          } else {
            do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
            goto error;
          }
        } else if (parser->index == 4 && parser->method == HTTP_PROPFIND && ch == 'P') {
          parser->method = HTTP_PROPPATCH;
        } else {
          do { parser->http_errno = (HPE_INVALID_METHOD); } while(0);
          goto error;
        }

        ++parser->index;
        break;
      }

      case s_req_spaces_before_url:
      {
        if (ch == ' ') break;

        do { if (!url_mark) { url_mark = p; } } while (0);
        if (parser->method == HTTP_CONNECT) {
          parser->state = s_req_server_start;
        }

        parser->state = parse_url_char((enum state)parser->state, ch);
        if (parser->state == s_dead) {
          do { parser->http_errno = (HPE_INVALID_URL); } while(0);
          goto error;
        }

        break;
      }

      case s_req_schema:
      case s_req_schema_slash:
      case s_req_schema_slash_slash:
      case s_req_server_start:
      {
        switch (ch) {

          case ' ':
          case '\r':
          case '\n':
            do { parser->http_errno = (HPE_INVALID_URL); } while(0);
            goto error;
          default:
            parser->state = parse_url_char((enum state)parser->state, ch);
            if (parser->state == s_dead) {
              do { parser->http_errno = (HPE_INVALID_URL); } while(0);
              goto error;
            }
        }

        break;
      }

      case s_req_server:
      case s_req_server_with_at:
      case s_req_path:
      case s_req_query_string_start:
      case s_req_query_string:
      case s_req_fragment_start:
      case s_req_fragment:
      {
        switch (ch) {
          case ' ':
            parser->state = s_req_http_start;
            do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (url_mark) { if (settings->on_url) { if (0 != settings->on_url(parser, url_mark, (p - url_mark))) { do { parser->http_errno = (HPE_CB_url); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } url_mark = NULL; } } while (0);
            break;
          case '\r':
          case '\n':
            parser->http_major = 0;
            parser->http_minor = 9;
            parser->state = (ch == '\r') ?
              s_req_line_almost_done :
              s_header_field_start;
            do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (url_mark) { if (settings->on_url) { if (0 != settings->on_url(parser, url_mark, (p - url_mark))) { do { parser->http_errno = (HPE_CB_url); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } url_mark = NULL; } } while (0);
            break;
          default:
            parser->state = parse_url_char((enum state)parser->state, ch);
            if (parser->state == s_dead) {
              do { parser->http_errno = (HPE_INVALID_URL); } while(0);
              goto error;
            }
        }
        break;
      }

      case s_req_http_start:
        switch (ch) {
          case 'H':
            parser->state = s_req_http_H;
            break;
          case ' ':
            break;
          default:
            do { parser->http_errno = (HPE_INVALID_CONSTANT); } while(0);
            goto error;
        }
        break;

      case s_req_http_H:
        do { if (ch != 'T') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_req_http_HT;
        break;

      case s_req_http_HT:
        do { if (ch != 'T') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_req_http_HTT;
        break;

      case s_req_http_HTT:
        do { if (ch != 'P') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_req_http_HTTP;
        break;

      case s_req_http_HTTP:
        do { if (ch != '/') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_req_first_http_major;
        break;


      case s_req_first_http_major:
        if (ch < '1' || ch > '9') {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_major = ch - '0';
        parser->state = s_req_http_major;
        break;


      case s_req_http_major:
      {
        if (ch == '.') {
          parser->state = s_req_first_http_minor;
          break;
        }

        if (!((ch) >= '0' && (ch) <= '9')) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_major *= 10;
        parser->http_major += ch - '0';

        if (parser->http_major > 999) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        break;
      }


      case s_req_first_http_minor:
        if (!((ch) >= '0' && (ch) <= '9')) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_minor = ch - '0';
        parser->state = s_req_http_minor;
        break;


      case s_req_http_minor:
      {
        if (ch == '\r') {
          parser->state = s_req_line_almost_done;
          break;
        }

        if (ch == '\n') {
          parser->state = s_header_field_start;
          break;
        }



        if (!((ch) >= '0' && (ch) <= '9')) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        parser->http_minor *= 10;
        parser->http_minor += ch - '0';

        if (parser->http_minor > 999) {
          do { parser->http_errno = (HPE_INVALID_VERSION); } while(0);
          goto error;
        }

        break;
      }


      case s_req_line_almost_done:
      {
        if (ch != '\n') {
          do { parser->http_errno = (HPE_LF_EXPECTED); } while(0);
          goto error;
        }

        parser->state = s_header_field_start;
        break;
      }

      case s_header_field_start:
      {
        if (ch == '\r') {
          parser->state = s_headers_almost_done;
          break;
        }

        if (ch == '\n') {


          parser->state = s_headers_almost_done;
          goto reexecute_byte;
        }

        c = (tokens[(unsigned char)ch]);

        if (!c) {
          do { parser->http_errno = (HPE_INVALID_HEADER_TOKEN); } while(0);
          goto error;
        }

        do { if (!header_field_mark) { header_field_mark = p; } } while (0);

        parser->index = 0;
        parser->state = s_header_field;

        switch (c) {
          case 'c':
            parser->header_state = h_C;
            break;

          case 'p':
            parser->header_state = h_matching_proxy_connection;
            break;

          case 't':
            parser->header_state = h_matching_transfer_encoding;
            break;

          case 'u':
            parser->header_state = h_matching_upgrade;
            break;

          default:
            parser->header_state = h_general;
            break;
        }
        break;
      }

      case s_header_field:
      {
        c = (tokens[(unsigned char)ch]);

        if (c) {
          switch (parser->header_state) {
            case h_general:
              break;

            case h_C:
              parser->index++;
              parser->header_state = (c == 'o' ? h_CO : h_general);
              break;

            case h_CO:
              parser->index++;
              parser->header_state = (c == 'n' ? h_CON : h_general);
              break;

            case h_CON:
              parser->index++;
              switch (c) {
                case 'n':
                  parser->header_state = h_matching_connection;
                  break;
                case 't':
                  parser->header_state = h_matching_content_length;
                  break;
                default:
                  parser->header_state = h_general;
                  break;
              }
              break;



            case h_matching_connection:
              parser->index++;
              if (parser->index > sizeof("connection")-1
                  || c != "connection"[parser->index]) {
                parser->header_state = h_general;
              } else if (parser->index == sizeof("connection")-2) {
                parser->header_state = h_connection;
              }
              break;



            case h_matching_proxy_connection:
              parser->index++;
              if (parser->index > sizeof("proxy-connection")-1
                  || c != "proxy-connection"[parser->index]) {
                parser->header_state = h_general;
              } else if (parser->index == sizeof("proxy-connection")-2) {
                parser->header_state = h_connection;
              }
              break;



            case h_matching_content_length:
              parser->index++;
              if (parser->index > sizeof("content-length")-1
                  || c != "content-length"[parser->index]) {
                parser->header_state = h_general;
              } else if (parser->index == sizeof("content-length")-2) {
                parser->header_state = h_content_length;
              }
              break;



            case h_matching_transfer_encoding:
              parser->index++;
              if (parser->index > sizeof("transfer-encoding")-1
                  || c != "transfer-encoding"[parser->index]) {
                parser->header_state = h_general;
              } else if (parser->index == sizeof("transfer-encoding")-2) {
                parser->header_state = h_transfer_encoding;
              }
              break;



            case h_matching_upgrade:
              parser->index++;
              if (parser->index > sizeof("upgrade")-1
                  || c != "upgrade"[parser->index]) {
                parser->header_state = h_general;
              } else if (parser->index == sizeof("upgrade")-2) {
                parser->header_state = h_upgrade;
              }
              break;

            case h_connection:
            case h_content_length:
            case h_transfer_encoding:
            case h_upgrade:
              if (ch != ' ') parser->header_state = h_general;
              break;

            default:
              assert(0 && "Unknown header_state");
              break;
          }
          break;
        }

        if (ch == ':') {
          parser->state = s_header_value_discard_ws;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_field_mark) { if (settings->on_header_field) { if (0 != settings->on_header_field(parser, header_field_mark, (p - header_field_mark))) { do { parser->http_errno = (HPE_CB_header_field); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } header_field_mark = NULL; } } while (0);
          break;
        }

        if (ch == '\r') {
          parser->state = s_header_almost_done;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_field_mark) { if (settings->on_header_field) { if (0 != settings->on_header_field(parser, header_field_mark, (p - header_field_mark))) { do { parser->http_errno = (HPE_CB_header_field); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } header_field_mark = NULL; } } while (0);
          break;
        }

        if (ch == '\n') {
          parser->state = s_header_field_start;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_field_mark) { if (settings->on_header_field) { if (0 != settings->on_header_field(parser, header_field_mark, (p - header_field_mark))) { do { parser->http_errno = (HPE_CB_header_field); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } header_field_mark = NULL; } } while (0);
          break;
        }

        do { parser->http_errno = (HPE_INVALID_HEADER_TOKEN); } while(0);
        goto error;
      }

      case s_header_value_discard_ws:
        if (ch == ' ' || ch == '\t') break;

        if (ch == '\r') {
          parser->state = s_header_value_discard_ws_almost_done;
          break;
        }

        if (ch == '\n') {
          parser->state = s_header_value_discard_lws;
          break;
        }



      case s_header_value_start:
      {
        do { if (!header_value_mark) { header_value_mark = p; } } while (0);

        parser->state = s_header_value;
        parser->index = 0;

        c = (unsigned char)(ch | 0x20);

        switch (parser->header_state) {
          case h_upgrade:
            parser->flags |= F_UPGRADE;
            parser->header_state = h_general;
            break;

          case h_transfer_encoding:

            if ('c' == c) {
              parser->header_state = h_matching_transfer_encoding_chunked;
            } else {
              parser->header_state = h_general;
            }
            break;

          case h_content_length:
            if (!((ch) >= '0' && (ch) <= '9')) {
              do { parser->http_errno = (HPE_INVALID_CONTENT_LENGTH); } while(0);
              goto error;
            }

            parser->content_length = ch - '0';
            break;

          case h_connection:

            if (c == 'k') {
              parser->header_state = h_matching_connection_keep_alive;

            } else if (c == 'c') {
              parser->header_state = h_matching_connection_close;
            } else {
              parser->header_state = h_general;
            }
            break;

          default:
            parser->header_state = h_general;
            break;
        }
        break;
      }

      case s_header_value:
      {

        if (ch == '\r') {
          parser->state = s_header_almost_done;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_value_mark) { if (settings->on_header_value) { if (0 != settings->on_header_value(parser, header_value_mark, (p - header_value_mark))) { do { parser->http_errno = (HPE_CB_header_value); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } header_value_mark = NULL; } } while (0);
          break;
        }

        if (ch == '\n') {
          parser->state = s_header_almost_done;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_value_mark) { if (settings->on_header_value) { if (0 != settings->on_header_value(parser, header_value_mark, (p - header_value_mark))) { do { parser->http_errno = (HPE_CB_header_value); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } header_value_mark = NULL; } } while (0);
          goto reexecute_byte;
        }

        c = (unsigned char)(ch | 0x20);

        switch (parser->header_state) {
          case h_general:
            break;

          case h_connection:
          case h_transfer_encoding:
            assert(0 && "Shouldn't get here.");
            break;

          case h_content_length:
          {
            uint64_t t;

            if (ch == ' ') break;

            if (!((ch) >= '0' && (ch) <= '9')) {
              do { parser->http_errno = (HPE_INVALID_CONTENT_LENGTH); } while(0);
              goto error;
            }

            t = parser->content_length;
            t *= 10;
            t += ch - '0';


            if ((((uint64_t) -1) - 10) / 10 < parser->content_length) {
              do { parser->http_errno = (HPE_INVALID_CONTENT_LENGTH); } while(0);
              goto error;
            }

            parser->content_length = t;
            break;
          }


          case h_matching_transfer_encoding_chunked:
            parser->index++;
            if (parser->index > sizeof("chunked")-1
                || c != "chunked"[parser->index]) {
              parser->header_state = h_general;
            } else if (parser->index == sizeof("chunked")-2) {
              parser->header_state = h_transfer_encoding_chunked;
            }
            break;


          case h_matching_connection_keep_alive:
            parser->index++;
            if (parser->index > sizeof("keep-alive")-1
                || c != "keep-alive"[parser->index]) {
              parser->header_state = h_general;
            } else if (parser->index == sizeof("keep-alive")-2) {
              parser->header_state = h_connection_keep_alive;
            }
            break;


          case h_matching_connection_close:
            parser->index++;
            if (parser->index > sizeof("close")-1 || c != "close"[parser->index]) {
              parser->header_state = h_general;
            } else if (parser->index == sizeof("close")-2) {
              parser->header_state = h_connection_close;
            }
            break;

          case h_transfer_encoding_chunked:
          case h_connection_keep_alive:
          case h_connection_close:
            if (ch != ' ') parser->header_state = h_general;
            break;

          default:
            parser->state = s_header_value;
            parser->header_state = h_general;
            break;
        }
        break;
      }

      case s_header_almost_done:
      {
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);

        parser->state = s_header_value_lws;
        break;
      }

      case s_header_value_lws:
      {
        if (ch == ' ' || ch == '\t') {
          parser->state = s_header_value_start;
          goto reexecute_byte;
        }


        switch (parser->header_state) {
          case h_connection_keep_alive:
            parser->flags |= F_CONNECTION_KEEP_ALIVE;
            break;
          case h_connection_close:
            parser->flags |= F_CONNECTION_CLOSE;
            break;
          case h_transfer_encoding_chunked:
            parser->flags |= F_CHUNKED;
            break;
          default:
            break;
        }

        parser->state = s_header_field_start;
        goto reexecute_byte;
      }

      case s_header_value_discard_ws_almost_done:
      {
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_header_value_discard_lws;
        break;
      }

      case s_header_value_discard_lws:
      {
        if (ch == ' ' || ch == '\t') {
          parser->state = s_header_value_discard_ws;
          break;
        } else {

          do { if (!header_value_mark) { header_value_mark = p; } } while (0);
          parser->state = s_header_field_start;
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_value_mark) { if (settings->on_header_value) { if (0 != settings->on_header_value(parser, header_value_mark, (p - header_value_mark))) { do { parser->http_errno = (HPE_CB_header_value); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } header_value_mark = NULL; } } while (0);
          goto reexecute_byte;
        }
      }

      case s_headers_almost_done:
      {
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);

        if (parser->flags & F_TRAILING) {

          parser->state = (http_should_keep_alive(parser) ? (parser->type == HTTP_REQUEST ? s_start_req : s_start_res) : s_dead);
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
          break;
        }

        parser->state = s_headers_done;


        parser->upgrade =
          (parser->flags & F_UPGRADE || parser->method == HTTP_CONNECT);

        if (settings->on_headers_complete) {
          switch (settings->on_headers_complete(parser)) {
            case 0:
              break;

            case 1:
              parser->flags |= F_SKIPBODY;
              break;

            default:
              do { parser->http_errno = (HPE_CB_headers_complete); } while(0);
              return p - data;
          }
        }

        if (((enum http_errno) (parser)->http_errno) != HPE_OK) {
          return p - data;
        }

        goto reexecute_byte;
      }

      case s_headers_done:
      {
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);

        parser->nread = 0;


        if (parser->upgrade) {
          parser->state = (http_should_keep_alive(parser) ? (parser->type == HTTP_REQUEST ? s_start_req : s_start_res) : s_dead);
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
          return (p - data) + 1;
        }

        if (parser->flags & F_SKIPBODY) {
          parser->state = (http_should_keep_alive(parser) ? (parser->type == HTTP_REQUEST ? s_start_req : s_start_res) : s_dead);
          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
        } else if (parser->flags & F_CHUNKED) {

          parser->state = s_chunk_size_start;
        } else {
          if (parser->content_length == 0) {

            parser->state = (http_should_keep_alive(parser) ? (parser->type == HTTP_REQUEST ? s_start_req : s_start_res) : s_dead);
            do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
          } else if (parser->content_length != ((uint64_t) -1)) {

            parser->state = s_body_identity;
          } else {
            if (parser->type == HTTP_REQUEST ||
                !http_message_needs_eof(parser)) {

              parser->state = (http_should_keep_alive(parser) ? (parser->type == HTTP_REQUEST ? s_start_req : s_start_res) : s_dead);
              do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
            } else {

              parser->state = s_body_identity_eof;
            }
          }
        }

        break;
      }

      case s_body_identity:
      {
        uint64_t to_read = ((parser->content_length) < ((uint64_t) ((data + len) - p)) ? (parser->content_length) : ((uint64_t) ((data + len) - p)))
                                                             ;

        assert(parser->content_length != 0
            && parser->content_length != ((uint64_t) -1));






        do { if (!body_mark) { body_mark = p; } } while (0);
        parser->content_length -= to_read;
        p += to_read - 1;

        if (parser->content_length == 0) {
          parser->state = s_message_done;

          do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (body_mark) { if (settings->on_body) { if (0 != settings->on_body(parser, body_mark, (p - body_mark + 1))) { do { parser->http_errno = (HPE_CB_body); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } body_mark = NULL; } } while (0);
          goto reexecute_byte;
        }

        break;
      }


      case s_body_identity_eof:
        do { if (!body_mark) { body_mark = p; } } while (0);
        p = data + len - 1;

        break;

      case s_message_done:
        parser->state = (http_should_keep_alive(parser) ? (parser->type == HTTP_REQUEST ? s_start_req : s_start_res) : s_dead);
        do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (settings->on_message_complete) { if (0 != settings->on_message_complete(parser)) { do { parser->http_errno = (HPE_CB_message_complete); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } } while (0);
        break;

      case s_chunk_size_start:
      {
        assert(parser->nread == 1);
        assert(parser->flags & F_CHUNKED);

        unhex_val = unhex[(unsigned char)ch];
        if (unhex_val == -1) {
          do { parser->http_errno = (HPE_INVALID_CHUNK_SIZE); } while(0);
          goto error;
        }

        parser->content_length = unhex_val;
        parser->state = s_chunk_size;
        break;
      }

      case s_chunk_size:
      {
        uint64_t t;

        assert(parser->flags & F_CHUNKED);

        if (ch == '\r') {
          parser->state = s_chunk_size_almost_done;
          break;
        }

        unhex_val = unhex[(unsigned char)ch];

        if (unhex_val == -1) {
          if (ch == ';' || ch == ' ') {
            parser->state = s_chunk_parameters;
            break;
          }

          do { parser->http_errno = (HPE_INVALID_CHUNK_SIZE); } while(0);
          goto error;
        }

        t = parser->content_length;
        t *= 16;
        t += unhex_val;


        if ((((uint64_t) -1) - 16) / 16 < parser->content_length) {
          do { parser->http_errno = (HPE_INVALID_CONTENT_LENGTH); } while(0);
          goto error;
        }

        parser->content_length = t;
        break;
      }

      case s_chunk_parameters:
      {
        assert(parser->flags & F_CHUNKED);

        if (ch == '\r') {
          parser->state = s_chunk_size_almost_done;
          break;
        }
        break;
      }

      case s_chunk_size_almost_done:
      {
        assert(parser->flags & F_CHUNKED);
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);

        parser->nread = 0;

        if (parser->content_length == 0) {
          parser->flags |= F_TRAILING;
          parser->state = s_header_field_start;
        } else {
          parser->state = s_chunk_data;
        }
        break;
      }

      case s_chunk_data:
      {
        uint64_t to_read = ((parser->content_length) < ((uint64_t) ((data + len) - p)) ? (parser->content_length) : ((uint64_t) ((data + len) - p)))
                                                             ;

        assert(parser->flags & F_CHUNKED);
        assert(parser->content_length != 0
            && parser->content_length != ((uint64_t) -1));




        do { if (!body_mark) { body_mark = p; } } while (0);
        parser->content_length -= to_read;
        p += to_read - 1;

        if (parser->content_length == 0) {
          parser->state = s_chunk_data_almost_done;
        }

        break;
      }

      case s_chunk_data_almost_done:
        assert(parser->flags & F_CHUNKED);
        assert(parser->content_length == 0);
        do { if (ch != '\r') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->state = s_chunk_data_done;
        do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (body_mark) { if (settings->on_body) { if (0 != settings->on_body(parser, body_mark, (p - body_mark))) { do { parser->http_errno = (HPE_CB_body); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data + 1); } } body_mark = NULL; } } while (0);
        break;

      case s_chunk_data_done:
        assert(parser->flags & F_CHUNKED);
        do { if (ch != '\n') { do { parser->http_errno = (HPE_STRICT); } while(0); goto error; } } while (0);
        parser->nread = 0;
        parser->state = s_chunk_size_start;
        break;

      default:
        assert(0 && "unhandled state");
        do { parser->http_errno = (HPE_INVALID_INTERNAL_STATE); } while(0);
        goto error;
    }
  }

  assert(((header_field_mark ? 1 : 0) +
          (header_value_mark ? 1 : 0) +
          (url_mark ? 1 : 0) +
          (body_mark ? 1 : 0) +
          (status_mark ? 1 : 0)) <= 1);

  do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_field_mark) { if (settings->on_header_field) { if (0 != settings->on_header_field(parser, header_field_mark, (p - header_field_mark))) { do { parser->http_errno = (HPE_CB_header_field); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } header_field_mark = NULL; } } while (0);
  do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (header_value_mark) { if (settings->on_header_value) { if (0 != settings->on_header_value(parser, header_value_mark, (p - header_value_mark))) { do { parser->http_errno = (HPE_CB_header_value); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } header_value_mark = NULL; } } while (0);
  do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (url_mark) { if (settings->on_url) { if (0 != settings->on_url(parser, url_mark, (p - url_mark))) { do { parser->http_errno = (HPE_CB_url); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } url_mark = NULL; } } while (0);
  do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (body_mark) { if (settings->on_body) { if (0 != settings->on_body(parser, body_mark, (p - body_mark))) { do { parser->http_errno = (HPE_CB_body); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } body_mark = NULL; } } while (0);
  do { assert(((enum http_errno) (parser)->http_errno) == HPE_OK); if (status_mark) { if (settings->on_status) { if (0 != settings->on_status(parser, status_mark, (p - status_mark))) { do { parser->http_errno = (HPE_CB_status); } while(0); } if (((enum http_errno) (parser)->http_errno) != HPE_OK) { return (p - data); } } status_mark = NULL; } } while (0);

  return len;

error:
  if (((enum http_errno) (parser)->http_errno) == HPE_OK) {
    do { parser->http_errno = (HPE_UNKNOWN); } while(0);
  }

  return (p - data);
}



inline int
http_message_needs_eof (const http_parser *parser)
{
  if (parser->type == HTTP_REQUEST) {
    return 0;
  }


  if (parser->status_code / 100 == 1 ||
      parser->status_code == 204 ||
      parser->status_code == 304 ||
      parser->flags & F_SKIPBODY) {
    return 0;
  }

  if ((parser->flags & F_CHUNKED) || parser->content_length != ((uint64_t) -1)) {
    return 0;
  }

  return 1;
}


inline int
http_should_keep_alive (const http_parser *parser)
{
  if (parser->http_major > 0 && parser->http_minor > 0) {

    if (parser->flags & F_CONNECTION_CLOSE) {
      return 0;
    }
  } else {

    if (!(parser->flags & F_CONNECTION_KEEP_ALIVE)) {
      return 0;
    }
  }

  return !http_message_needs_eof(parser);
}


inline const char *
http_method_str (enum http_method m)
{
static const char *method_strings[] =
  {

  "DELETE", "GET", "HEAD", "POST", "PUT", "CONNECT", "OPTIONS", "TRACE", "PATCH", "PURGE", "COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND", "PROPPATCH", "SEARCH", "UNLOCK", "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE", "M-SEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "MKCALENDAR",

  };
  return ((unsigned int) (m) < (sizeof(method_strings) / sizeof((method_strings)[0])) ? (method_strings)[(m)] : ("<unknown>"));
}


inline void
http_parser_init (http_parser *parser, enum http_parser_type t)
{
  void *data = parser->data;
  memset(parser, 0, sizeof(*parser));
  parser->data = data;
  parser->type = t;
  parser->state = (t == HTTP_REQUEST ? s_start_req : (t == HTTP_RESPONSE ? s_start_res : s_start_req_or_res));
  parser->http_errno = HPE_OK;
}

inline const char *
http_errno_name(enum http_errno err) {


static struct {
  const char *name;
  const char *description;
} http_strerror_tab[] = {
  { "HPE_" "OK", "success" }, { "HPE_" "CB_message_begin", "the on_message_begin callback failed" }, { "HPE_" "CB_url", "the on_url callback failed" }, { "HPE_" "CB_header_field", "the on_header_field callback failed" }, { "HPE_" "CB_header_value", "the on_header_value callback failed" }, { "HPE_" "CB_headers_complete", "the on_headers_complete callback failed" }, { "HPE_" "CB_body", "the on_body callback failed" }, { "HPE_" "CB_message_complete", "the on_message_complete callback failed" }, { "HPE_" "CB_status", "the on_status callback failed" }, { "HPE_" "INVALID_EOF_STATE", "stream ended at an unexpected time" }, { "HPE_" "HEADER_OVERFLOW", "too many header bytes seen; overflow detected" }, { "HPE_" "CLOSED_CONNECTION", "data received after completed connection: close message" }, { "HPE_" "INVALID_VERSION", "invalid HTTP version" }, { "HPE_" "INVALID_STATUS", "invalid HTTP status code" }, { "HPE_" "INVALID_METHOD", "invalid HTTP method" }, { "HPE_" "INVALID_URL", "invalid URL" }, { "HPE_" "INVALID_HOST", "invalid host" }, { "HPE_" "INVALID_PORT", "invalid port" }, { "HPE_" "INVALID_PATH", "invalid path" }, { "HPE_" "INVALID_QUERY_STRING", "invalid query string" }, { "HPE_" "INVALID_FRAGMENT", "invalid fragment" }, { "HPE_" "LF_EXPECTED", "CROW_LF character expected" }, { "HPE_" "INVALID_HEADER_TOKEN", "invalid character in header" }, { "HPE_" "INVALID_CONTENT_LENGTH", "invalid character in content-length header" }, { "HPE_" "INVALID_CHUNK_SIZE", "invalid character in chunk size header" }, { "HPE_" "INVALID_CONSTANT", "invalid constant string" }, { "HPE_" "INVALID_INTERNAL_STATE", "encountered unexpected internal state" }, { "HPE_" "STRICT", "strict mode assertion failed" }, { "HPE_" "PAUSED", "parser is paused" }, { "HPE_" "UNKNOWN", "an unknown error occurred" },
};

  assert(err < (sizeof(http_strerror_tab)/sizeof(http_strerror_tab[0])));
  return http_strerror_tab[err].name;
}

inline const char *
http_errno_description(enum http_errno err) {


static struct {
  const char *name;
  const char *description;
} http_strerror_tab[] = {
  { "HPE_" "OK", "success" }, { "HPE_" "CB_message_begin", "the on_message_begin callback failed" }, { "HPE_" "CB_url", "the on_url callback failed" }, { "HPE_" "CB_header_field", "the on_header_field callback failed" }, { "HPE_" "CB_header_value", "the on_header_value callback failed" }, { "HPE_" "CB_headers_complete", "the on_headers_complete callback failed" }, { "HPE_" "CB_body", "the on_body callback failed" }, { "HPE_" "CB_message_complete", "the on_message_complete callback failed" }, { "HPE_" "CB_status", "the on_status callback failed" }, { "HPE_" "INVALID_EOF_STATE", "stream ended at an unexpected time" }, { "HPE_" "HEADER_OVERFLOW", "too many header bytes seen; overflow detected" }, { "HPE_" "CLOSED_CONNECTION", "data received after completed connection: close message" }, { "HPE_" "INVALID_VERSION", "invalid HTTP version" }, { "HPE_" "INVALID_STATUS", "invalid HTTP status code" }, { "HPE_" "INVALID_METHOD", "invalid HTTP method" }, { "HPE_" "INVALID_URL", "invalid URL" }, { "HPE_" "INVALID_HOST", "invalid host" }, { "HPE_" "INVALID_PORT", "invalid port" }, { "HPE_" "INVALID_PATH", "invalid path" }, { "HPE_" "INVALID_QUERY_STRING", "invalid query string" }, { "HPE_" "INVALID_FRAGMENT", "invalid fragment" }, { "HPE_" "LF_EXPECTED", "CROW_LF character expected" }, { "HPE_" "INVALID_HEADER_TOKEN", "invalid character in header" }, { "HPE_" "INVALID_CONTENT_LENGTH", "invalid character in content-length header" }, { "HPE_" "INVALID_CHUNK_SIZE", "invalid character in chunk size header" }, { "HPE_" "INVALID_CONSTANT", "invalid constant string" }, { "HPE_" "INVALID_INTERNAL_STATE", "encountered unexpected internal state" }, { "HPE_" "STRICT", "strict mode assertion failed" }, { "HPE_" "PAUSED", "parser is paused" }, { "HPE_" "UNKNOWN", "an unknown error occurred" },
};

  assert(err < (sizeof(http_strerror_tab)/sizeof(http_strerror_tab[0])));
  return http_strerror_tab[err].description;
}

inline static enum http_host_state
http_parse_host_char(enum http_host_state s, const char ch) {
  switch(s) {
    case s_http_userinfo:
    case s_http_userinfo_start:
      if (ch == '@') {
        return s_http_host_start;
      }

      if (((((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z') || ((ch) >= '0' && (ch) <= '9')) || ((ch) == '-' || (ch) == '_' || (ch) == '.' || (ch) == '!' || (ch) == '~' || (ch) == '*' || (ch) == '\'' || (ch) == '(' || (ch) == ')') || (ch) == '%' || (ch) == ';' || (ch) == ':' || (ch) == '&' || (ch) == '=' || (ch) == '+' || (ch) == '$' || (ch) == ',')) {
        return s_http_userinfo;
      }
      break;

    case s_http_host_start:
      if (ch == '[') {
        return s_http_host_v6_start;
      }

      if (((((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z') || ((ch) >= '0' && (ch) <= '9')) || (ch) == '.' || (ch) == '-')) {
        return s_http_host;
      }

      break;

    case s_http_host:
      if (((((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'z') || ((ch) >= '0' && (ch) <= '9')) || (ch) == '.' || (ch) == '-')) {
        return s_http_host;
      }


    case s_http_host_v6_end:
      if (ch == ':') {
        return s_http_host_port_start;
      }

      break;

    case s_http_host_v6:
      if (ch == ']') {
        return s_http_host_v6_end;
      }


    case s_http_host_v6_start:
      if ((((ch) >= '0' && (ch) <= '9') || ((unsigned char)(ch | 0x20) >= 'a' && (unsigned char)(ch | 0x20) <= 'f')) || ch == ':' || ch == '.') {
        return s_http_host_v6;
      }

      break;

    case s_http_host_port:
    case s_http_host_port_start:
      if (((ch) >= '0' && (ch) <= '9')) {
        return s_http_host_port;
      }

      break;

    default:
      break;
  }
  return s_http_host_dead;
}

inline int
http_parse_host(const char * buf, struct http_parser_url *u, int found_at) {
  enum http_host_state s;

  const char *p;
  size_t buflen = u->field_data[UF_HOST].off + u->field_data[UF_HOST].len;

  u->field_data[UF_HOST].len = 0;

  s = found_at ? s_http_userinfo_start : s_http_host_start;

  for (p = buf + u->field_data[UF_HOST].off; p < buf + buflen; p++) {
    enum http_host_state new_s = http_parse_host_char(s, *p);

    if (new_s == s_http_host_dead) {
      return 1;
    }

    switch(new_s) {
      case s_http_host:
        if (s != s_http_host) {
          u->field_data[UF_HOST].off = p - buf;
        }
        u->field_data[UF_HOST].len++;
        break;

      case s_http_host_v6:
        if (s != s_http_host_v6) {
          u->field_data[UF_HOST].off = p - buf;
        }
        u->field_data[UF_HOST].len++;
        break;

      case s_http_host_port:
        if (s != s_http_host_port) {
          u->field_data[UF_PORT].off = p - buf;
          u->field_data[UF_PORT].len = 0;
          u->field_set |= (1 << UF_PORT);
        }
        u->field_data[UF_PORT].len++;
        break;

      case s_http_userinfo:
        if (s != s_http_userinfo) {
          u->field_data[UF_USERINFO].off = p - buf ;
          u->field_data[UF_USERINFO].len = 0;
          u->field_set |= (1 << UF_USERINFO);
        }
        u->field_data[UF_USERINFO].len++;
        break;

      default:
        break;
    }
    s = new_s;
  }


  switch (s) {
    case s_http_host_start:
    case s_http_host_v6_start:
    case s_http_host_v6:
    case s_http_host_port_start:
    case s_http_userinfo:
    case s_http_userinfo_start:
      return 1;
    default:
      break;
  }

  return 0;
}

inline int
http_parser_parse_url(const char *buf, size_t buflen, int is_connect,
                      struct http_parser_url *u)
{
  enum state s;
  const char *p;
  enum http_parser_url_fields uf, old_uf;
  int found_at = 0;

  u->port = u->field_set = 0;
  s = is_connect ? s_req_server_start : s_req_spaces_before_url;
  old_uf = UF_MAX;

  for (p = buf; p < buf + buflen; p++) {
    s = parse_url_char(s, *p);


    switch (s) {
      case s_dead:
        return 1;


      case s_req_schema_slash:
      case s_req_schema_slash_slash:
      case s_req_server_start:
      case s_req_query_string_start:
      case s_req_fragment_start:
        continue;

      case s_req_schema:
        uf = UF_SCHEMA;
        break;

      case s_req_server_with_at:
        found_at = 1;


      case s_req_server:
        uf = UF_HOST;
        break;

      case s_req_path:
        uf = UF_PATH;
        break;

      case s_req_query_string:
        uf = UF_QUERY;
        break;

      case s_req_fragment:
        uf = UF_FRAGMENT;
        break;

      default:
        assert(!"Unexpected state");
        return 1;
    }


    if (uf == old_uf) {
      u->field_data[uf].len++;
      continue;
    }

    u->field_data[uf].off = p - buf;
    u->field_data[uf].len = 1;

    u->field_set |= (1 << uf);
    old_uf = uf;
  }



  if ((u->field_set & ((1 << UF_SCHEMA) | (1 << UF_HOST))) != 0) {
    if (http_parse_host(buf, u, found_at) != 0) {
      return 1;
    }
  }


  if (is_connect && u->field_set != ((1 << UF_HOST)|(1 << UF_PORT))) {
    return 1;
  }

  if (u->field_set & (1 << UF_PORT)) {

    unsigned long v = strtoul(buf + u->field_data[UF_PORT].off, NULL, 10);


    if (v > 0xffff) {
      return 1;
    }

    u->port = (uint16_t) v;
  }

  return 0;
}

inline void
http_parser_pause(http_parser *parser, int paused) {




  if (((enum http_errno) (parser)->http_errno) == HPE_OK ||
      ((enum http_errno) (parser)->http_errno) == HPE_PAUSED) {
    do { parser->http_errno = ((paused) ? HPE_PAUSED : HPE_OK); } while(0);
  } else {
    assert(0 && "Attempting to pause parser in error state");
  }
}

inline int
http_body_is_final(const struct http_parser *parser) {
    return parser->state == s_message_done;
}

inline unsigned long
http_parser_version(void) {
  return 2 * 0x10000 |
         3 * 0x00100 |
         0 * 0x00001;
}

}


       





namespace crow
{
    struct ci_hash
    {
        size_t operator()(const std::string& key) const
        {
            std::size_t seed = 0;
            std::locale locale;

            for(auto c : key)
            {
                boost::hash_combine(seed, std::toupper(c, locale));
            }

            return seed;
        }
    };

    struct ci_key_eq
    {
        bool operator()(const std::string& l, const std::string& r) const
        {
            return boost::iequals(l, r);
        }
    };

    using ci_map = std::unordered_multimap<std::string, std::string, ci_hash, ci_key_eq>;
}







namespace sha1
{
 class SHA1
 {
 public:
  typedef uint32_t digest32_t[5];
  typedef uint8_t digest8_t[20];
  inline static uint32_t LeftRotate(uint32_t value, size_t count) {
   return (value << count) ^ (value >> (32-count));
  }
  SHA1(){ reset(); }
  virtual ~SHA1() {}
  SHA1(const SHA1& s) { *this = s; }
  const SHA1& operator = (const SHA1& s) {
   memcpy(m_digest, s.m_digest, 5 * sizeof(uint32_t));
   memcpy(m_block, s.m_block, 64);
   m_blockByteIndex = s.m_blockByteIndex;
   m_byteCount = s.m_byteCount;
   return *this;
  }
  SHA1& reset() {
   m_digest[0] = 0x67452301;
   m_digest[1] = 0xEFCDAB89;
   m_digest[2] = 0x98BADCFE;
   m_digest[3] = 0x10325476;
   m_digest[4] = 0xC3D2E1F0;
   m_blockByteIndex = 0;
   m_byteCount = 0;
   return *this;
  }
  SHA1& processByte(uint8_t octet) {
   this->m_block[this->m_blockByteIndex++] = octet;
   ++this->m_byteCount;
   if(m_blockByteIndex == 64) {
    this->m_blockByteIndex = 0;
    processBlock();
   }
   return *this;
  }
  SHA1& processBlock(const void* const start, const void* const end) {
   const uint8_t* begin = static_cast<const uint8_t*>(start);
   const uint8_t* finish = static_cast<const uint8_t*>(end);
   while(begin != finish) {
    processByte(*begin);
    begin++;
   }
   return *this;
  }
  SHA1& processBytes(const void* const data, size_t len) {
   const uint8_t* block = static_cast<const uint8_t*>(data);
   processBlock(block, block + len);
   return *this;
  }
  const uint32_t* getDigest(digest32_t digest) {
   size_t bitCount = this->m_byteCount * 8;
   processByte(0x80);
   if (this->m_blockByteIndex > 56) {
    while (m_blockByteIndex != 0) {
     processByte(0);
    }
    while (m_blockByteIndex < 56) {
     processByte(0);
    }
   } else {
    while (m_blockByteIndex < 56) {
     processByte(0);
    }
   }
   processByte(0);
   processByte(0);
   processByte(0);
   processByte(0);
   processByte( static_cast<unsigned char>((bitCount>>24) & 0xFF));
   processByte( static_cast<unsigned char>((bitCount>>16) & 0xFF));
   processByte( static_cast<unsigned char>((bitCount>>8 ) & 0xFF));
   processByte( static_cast<unsigned char>((bitCount) & 0xFF));

   memcpy(digest, m_digest, 5 * sizeof(uint32_t));
   return digest;
  }
  const uint8_t* getDigestBytes(digest8_t digest) {
   digest32_t d32;
   getDigest(d32);
   size_t di = 0;
   digest[di++] = ((d32[0] >> 24) & 0xFF);
   digest[di++] = ((d32[0] >> 16) & 0xFF);
   digest[di++] = ((d32[0] >> 8) & 0xFF);
   digest[di++] = ((d32[0]) & 0xFF);

   digest[di++] = ((d32[1] >> 24) & 0xFF);
   digest[di++] = ((d32[1] >> 16) & 0xFF);
   digest[di++] = ((d32[1] >> 8) & 0xFF);
   digest[di++] = ((d32[1]) & 0xFF);

   digest[di++] = ((d32[2] >> 24) & 0xFF);
   digest[di++] = ((d32[2] >> 16) & 0xFF);
   digest[di++] = ((d32[2] >> 8) & 0xFF);
   digest[di++] = ((d32[2]) & 0xFF);

   digest[di++] = ((d32[3] >> 24) & 0xFF);
   digest[di++] = ((d32[3] >> 16) & 0xFF);
   digest[di++] = ((d32[3] >> 8) & 0xFF);
   digest[di++] = ((d32[3]) & 0xFF);

   digest[di++] = ((d32[4] >> 24) & 0xFF);
   digest[di++] = ((d32[4] >> 16) & 0xFF);
   digest[di++] = ((d32[4] >> 8) & 0xFF);
   digest[di++] = ((d32[4]) & 0xFF);
   return digest;
  }

 protected:
  void processBlock() {
   uint32_t w[80];
   for (size_t i = 0; i < 16; i++) {
    w[i] = (m_block[i*4 + 0] << 24);
    w[i] |= (m_block[i*4 + 1] << 16);
    w[i] |= (m_block[i*4 + 2] << 8);
    w[i] |= (m_block[i*4 + 3]);
   }
   for (size_t i = 16; i < 80; i++) {
    w[i] = LeftRotate((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
   }

   uint32_t a = m_digest[0];
   uint32_t b = m_digest[1];
   uint32_t c = m_digest[2];
   uint32_t d = m_digest[3];
   uint32_t e = m_digest[4];

   for (std::size_t i=0; i<80; ++i) {
    uint32_t f = 0;
    uint32_t k = 0;

    if (i<20) {
     f = (b & c) | (~b & d);
     k = 0x5A827999;
    } else if (i<40) {
     f = b ^ c ^ d;
     k = 0x6ED9EBA1;
    } else if (i<60) {
     f = (b & c) | (b & d) | (c & d);
     k = 0x8F1BBCDC;
    } else {
     f = b ^ c ^ d;
     k = 0xCA62C1D6;
    }
    uint32_t temp = LeftRotate(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = LeftRotate(b, 30);
    b = a;
    a = temp;
   }

   m_digest[0] += a;
   m_digest[1] += b;
   m_digest[2] += c;
   m_digest[3] += d;
   m_digest[4] += e;
  }
 private:
  digest32_t m_digest;
  uint8_t m_block[64];
  size_t m_blockByteIndex;
  size_t m_byteCount;
 };
}


       


       





namespace crow
{
    using namespace boost;
    using tcp = asio::ip::tcp;

    struct SocketAdaptor
    {
        using context = void;
        SocketAdaptor(boost::asio::io_service& io_service, context*)
            : socket_(io_service)
        {
        }

        boost::asio::io_service& get_io_service()
        {
            return static_cast<boost::asio::io_service&>(socket_.get_executor().context());
        }

        tcp::socket& raw_socket()
        {
            return socket_;
        }

        tcp::socket& socket()
        {
            return socket_;
        }

        tcp::endpoint remote_endpoint()
        {
            return socket_.remote_endpoint();
        }

        bool is_open()
        {
            return socket_.is_open();
        }

        void close()
        {
            boost::system::error_code ec;
            socket_.close(ec);
        }

        template <typename F>
        void start(F f)
        {
            f(boost::system::error_code());
        }

        tcp::socket socket_;
    };

}


       













namespace crow
{
    namespace mustache
    {
        class template_t;
    }

    namespace json
    {
        inline void escape(const std::string& str, std::string& ret)
        {
            ret.reserve(ret.size() + str.size()+str.size()/4);
            for(char c:str)
            {
                switch(c)
                {
                    case '"': ret += "\\\""; break;
                    case '\\': ret += "\\\\"; break;
                    case '\n': ret += "\\n"; break;
                    case '\b': ret += "\\b"; break;
                    case '\f': ret += "\\f"; break;
                    case '\r': ret += "\\r"; break;
                    case '\t': ret += "\\t"; break;
                    default:
                        if (0 <= c && c < 0x20)
                        {
                            ret += "\\u00";
                            auto to_hex = [](char c)
                            {
                                c = c&0xf;
                                if (c < 10)
                                    return '0' + c;
                                return 'a'+c-10;
                            };
                            ret += to_hex(c/16);
                            ret += to_hex(c%16);
                        }
                        else
                            ret += c;
                        break;
                }
            }
        }
        inline std::string escape(const std::string& str)
        {
            std::string ret;
            escape(str, ret);
            return ret;
        }

        enum class type : char
        {
            Null,
            False,
            True,
            Number,
            String,
            List,
            Object,
        };

        inline const char* get_type_str(type t) {
            switch(t){
                case type::Number: return "Number";
                case type::False: return "False";
                case type::True: return "True";
                case type::List: return "List";
                case type::String: return "String";
                case type::Object: return "Object";
                default: return "Unknown";
            }
        }

        enum class num_type : char {
            Signed_integer,
            Unsigned_integer,
            Floating_point,
            Null
        };

        class rvalue;
        rvalue load(const char* data, size_t size);

        namespace detail
        {

            struct r_string
                : boost::less_than_comparable<r_string>,
                boost::less_than_comparable<r_string, std::string>,
                boost::equality_comparable<r_string>,
                boost::equality_comparable<r_string, std::string>
            {
                r_string() {};
                r_string(char* s, char* e)
                    : s_(s), e_(e)
                {};
                ~r_string()
                {
                    if (owned_)
                        delete[] s_;
                }

                r_string(const r_string& r)
                {
                    *this = r;
                }

                r_string(r_string&& r)
                {
                    *this = r;
                }

                r_string& operator = (r_string&& r)
                {
                    s_ = r.s_;
                    e_ = r.e_;
                    owned_ = r.owned_;
                    if (r.owned_)
                        r.owned_ = 0;
                    return *this;
                }

                r_string& operator = (const r_string& r)
                {
                    s_ = r.s_;
                    e_ = r.e_;
                    owned_ = 0;
                    return *this;
                }

                operator std::string () const
                {
                    return std::string(s_, e_);
                }


                const char* begin() const { return s_; }
                const char* end() const { return e_; }
                size_t size() const { return end() - begin(); }

                using iterator = const char*;
                using const_iterator = const char*;

                char* s_;
                mutable char* e_;
                uint8_t owned_{0};
                friend std::ostream& operator << (std::ostream& os, const r_string& s)
                {
                    os << (std::string)s;
                    return os;
                }
            private:
                void force(char* s, uint32_t length)
                {
                    s_ = s;
                    e_ = s_ + length;
                    owned_ = 1;
                }
                friend rvalue crow::json::load(const char* data, size_t size);
            };

            inline bool operator < (const r_string& l, const r_string& r)
            {
                return boost::lexicographical_compare(l,r);
            }

            inline bool operator < (const r_string& l, const std::string& r)
            {
                return boost::lexicographical_compare(l,r);
            }

            inline bool operator > (const r_string& l, const std::string& r)
            {
                return boost::lexicographical_compare(r,l);
            }

            inline bool operator == (const r_string& l, const r_string& r)
            {
                return boost::equals(l,r);
            }

            inline bool operator == (const r_string& l, const std::string& r)
            {
                return boost::equals(l,r);
            }
        }

        class rvalue
        {
            static const int cached_bit = 2;
            static const int error_bit = 4;
        public:
            rvalue() noexcept : option_{error_bit}
            {}
            rvalue(type t) noexcept
                : lsize_{}, lremain_{}, t_{t}
            {}
            rvalue(type t, char* s, char* e) noexcept
                : start_{s},
                end_{e},
                t_{t}
            {
                determine_num_type();
            }

            rvalue(const rvalue& r)
            : start_(r.start_),
                end_(r.end_),
                key_(r.key_),
                t_(r.t_),
                nt_(r.nt_),
                option_(r.option_)
            {
                copy_l(r);
            }

            rvalue(rvalue&& r) noexcept
            {
                *this = std::move(r);
            }

            rvalue& operator = (const rvalue& r)
            {
                start_ = r.start_;
                end_ = r.end_;
                key_ = r.key_;
                t_ = r.t_;
                nt_ = r.nt_;
                option_ = r.option_;
                copy_l(r);
                return *this;
            }
            rvalue& operator = (rvalue&& r) noexcept
            {
                start_ = r.start_;
                end_ = r.end_;
                key_ = std::move(r.key_);
                l_ = std::move(r.l_);
                lsize_ = r.lsize_;
                lremain_ = r.lremain_;
                t_ = r.t_;
                nt_ = r.nt_;
                option_ = r.option_;
                return *this;
            }

            explicit operator bool() const noexcept
            {
                return (option_ & error_bit) == 0;
            }

            explicit operator int64_t() const
            {
                return i();
            }

            explicit operator uint64_t() const
            {
                return u();
            }

            explicit operator int() const
            {
                return (int)i();
            }

            type t() const
            {

                if (option_ & error_bit)
                {
                    throw std::runtime_error("invalid json object");
                }

                return t_;
            }

            num_type nt() const
            {

                if (option_ & error_bit)
                {
                    throw std::runtime_error("invalid json object");
                }

                return nt_;
            }

            int64_t i() const
            {

                switch (t()) {
                    case type::Number:
                    case type::String:
                        return boost::lexical_cast<int64_t>(start_, end_-start_);
                    default:
                        const std::string msg = "expected number, got: "
                            + std::string(get_type_str(t()));
                        throw std::runtime_error(msg);
                }

                return boost::lexical_cast<int64_t>(start_, end_-start_);
            }

            uint64_t u() const
            {

                switch (t()) {
                    case type::Number:
                    case type::String:
                        return boost::lexical_cast<uint64_t>(start_, end_-start_);
                    default:
                        throw std::runtime_error(std::string("expected number, got: ") + get_type_str(t()));
                }

                return boost::lexical_cast<uint64_t>(start_, end_-start_);
            }

            double d() const
            {

                if (t() != type::Number)
                    throw std::runtime_error("value is not number");

                return boost::lexical_cast<double>(start_, end_-start_);
            }

            bool b() const
            {

                if (t() != type::True && t() != type::False)
                    throw std::runtime_error("value is not boolean");

                return t() == type::True;
            }

            void unescape() const
            {
                if (*(start_-1))
                {
                    char* head = start_;
                    char* tail = start_;
                    while(head != end_)
                    {
                        if (*head == '\\')
                        {
                            switch(*++head)
                            {
                                case '"': *tail++ = '"'; break;
                                case '\\': *tail++ = '\\'; break;
                                case '/': *tail++ = '/'; break;
                                case 'b': *tail++ = '\b'; break;
                                case 'f': *tail++ = '\f'; break;
                                case 'n': *tail++ = '\n'; break;
                                case 'r': *tail++ = '\r'; break;
                                case 't': *tail++ = '\t'; break;
                                case 'u':
                                    {
                                        auto from_hex = [](char c)
                                        {
                                            if (c >= 'a')
                                                return c - 'a' + 10;
                                            if (c >= 'A')
                                                return c - 'A' + 10;
                                            return c - '0';
                                        };
                                        unsigned int code =
                                            (from_hex(head[1])<<12) +
                                            (from_hex(head[2])<< 8) +
                                            (from_hex(head[3])<< 4) +
                                            from_hex(head[4]);
                                        if (code >= 0x800)
                                        {
                                            *tail++ = 0xE0 | (code >> 12);
                                            *tail++ = 0x80 | ((code >> 6) & 0x3F);
                                            *tail++ = 0x80 | (code & 0x3F);
                                        }
                                        else if (code >= 0x80)
                                        {
                                            *tail++ = 0xC0 | (code >> 6);
                                            *tail++ = 0x80 | (code & 0x3F);
                                        }
                                        else
                                        {
                                            *tail++ = code;
                                        }
                                        head += 4;
                                    }
                                    break;
                            }
                        }
                        else
                            *tail++ = *head;
                        head++;
                    }
                    end_ = tail;
                    *end_ = 0;
                    *(start_-1) = 0;
                }
            }

            detail::r_string s() const
            {

                if (t() != type::String)
                    throw std::runtime_error("value is not string");

                unescape();
                return detail::r_string{start_, end_};
            }

            bool has(const char* str) const
            {
                return has(std::string(str));
            }

            bool has(const std::string& str) const
            {
                struct Pred
                {
                    bool operator()(const rvalue& l, const rvalue& r) const
                    {
                        return l.key_ < r.key_;
                    };
                    bool operator()(const rvalue& l, const std::string& r) const
                    {
                        return l.key_ < r;
                    };
                    bool operator()(const std::string& l, const rvalue& r) const
                    {
                        return l < r.key_;
                    };
                };
                if (!is_cached())
                {
                    std::sort(begin(), end(), Pred());
                    set_cached();
                }
                auto it = lower_bound(begin(), end(), str, Pred());
                return it != end() && it->key_ == str;
            }

            int count(const std::string& str)
            {
                return has(str) ? 1 : 0;
            }

            rvalue* begin() const
            {

                if (t() != type::Object && t() != type::List)
                    throw std::runtime_error("value is not a container");

                return l_.get();
            }
            rvalue* end() const
            {

                if (t() != type::Object && t() != type::List)
                    throw std::runtime_error("value is not a container");

                return l_.get()+lsize_;
            }

            const detail::r_string& key() const
            {
                return key_;
            }

            size_t size() const
            {
                if (t() == type::String)
                    return s().size();

                if (t() != type::Object && t() != type::List)
                    throw std::runtime_error("value is not a container");

                return lsize_;
            }

            const rvalue& operator[](int index) const
            {

                if (t() != type::List)
                    throw std::runtime_error("value is not a list");
                if (index >= (int)lsize_ || index < 0)
                    throw std::runtime_error("list out of bound");

                return l_[index];
            }

            const rvalue& operator[](size_t index) const
            {

                if (t() != type::List)
                    throw std::runtime_error("value is not a list");
                if (index >= lsize_)
                    throw std::runtime_error("list out of bound");

                return l_[index];
            }

            const rvalue& operator[](const char* str) const
            {
                return this->operator[](std::string(str));
            }

            const rvalue& operator[](const std::string& str) const
            {

                if (t() != type::Object)
                    throw std::runtime_error("value is not an object");

                struct Pred
                {
                    bool operator()(const rvalue& l, const rvalue& r) const
                    {
                        return l.key_ < r.key_;
                    };
                    bool operator()(const rvalue& l, const std::string& r) const
                    {
                        return l.key_ < r;
                    };
                    bool operator()(const std::string& l, const rvalue& r) const
                    {
                        return l < r.key_;
                    };
                };
                if (!is_cached())
                {
                    std::sort(begin(), end(), Pred());
                    set_cached();
                }
                auto it = lower_bound(begin(), end(), str, Pred());
                if (it != end() && it->key_ == str)
                    return *it;

                throw std::runtime_error("cannot find key");




            }

            void set_error()
            {
                option_|=error_bit;
            }

            bool error() const
            {
                return (option_&error_bit)!=0;
            }
        private:
            bool is_cached() const
            {
                return (option_&cached_bit)!=0;
            }
            void set_cached() const
            {
                option_ |= cached_bit;
            }
            void copy_l(const rvalue& r)
            {
                if (r.t() != type::Object && r.t() != type::List)
                    return;
                lsize_ = r.lsize_;
                lremain_ = 0;
                l_.reset(new rvalue[lsize_]);
                std::copy(r.begin(), r.end(), begin());
            }

            void emplace_back(rvalue&& v)
            {
                if (!lremain_)
                {
                    int new_size = lsize_ + lsize_;
                    if (new_size - lsize_ > 60000)
                        new_size = lsize_ + 60000;
                    if (new_size < 4)
                        new_size = 4;
                    rvalue* p = new rvalue[new_size];
                    rvalue* p2 = p;
                    for(auto& x : *this)
                        *p2++ = std::move(x);
                    l_.reset(p);
                    lremain_ = new_size - lsize_;
                }
                l_[lsize_++] = std::move(v);
                lremain_ --;
            }


            void determine_num_type()
            {
                if (t_ != type::Number)
                {
                    nt_ = num_type::Null;
                    return;
                }

                const std::size_t len = end_ - start_;
                const bool has_minus = std::memchr(start_, '-', len) != nullptr;
                const bool has_e = std::memchr(start_, 'e', len) != nullptr
                                || std::memchr(start_, 'E', len) != nullptr;
                const bool has_dec_sep = std::memchr(start_, '.', len) != nullptr;
                if (has_dec_sep || has_e)
                  nt_ = num_type::Floating_point;
                else if (has_minus)
                  nt_ = num_type::Signed_integer;
                else
                  nt_ = num_type::Unsigned_integer;
            }

            mutable char* start_;
            mutable char* end_;
            detail::r_string key_;
            std::unique_ptr<rvalue[]> l_;
            uint32_t lsize_;
            uint16_t lremain_;
            type t_;
            num_type nt_{num_type::Null};
            mutable uint8_t option_{0};

            friend rvalue load_nocopy_internal(char* data, size_t size);
            friend rvalue load(const char* data, size_t size);
            friend std::ostream& operator <<(std::ostream& os, const rvalue& r)
            {
                switch(r.t_)
                {

                case type::Null: os << "null"; break;
                case type::False: os << "false"; break;
                case type::True: os << "true"; break;
                case type::Number:
                    {
                        switch (r.nt())
                        {
                        case num_type::Floating_point: os << r.d(); break;
                        case num_type::Signed_integer: os << r.i(); break;
                        case num_type::Unsigned_integer: os << r.u(); break;
                        case num_type::Null: throw std::runtime_error("Number with num_type Null");
                        }
                    }
                    break;
                case type::String: os << '"' << r.s() << '"'; break;
                case type::List:
                    {
                        os << '[';
                        bool first = true;
                        for(auto& x : r)
                        {
                            if (!first)
                                os << ',';
                            first = false;
                            os << x;
                        }
                        os << ']';
                    }
                    break;
                case type::Object:
                    {
                        os << '{';
                        bool first = true;
                        for(auto& x : r)
                        {
                            if (!first)
                                os << ',';
                            os << '"' << escape(x.key_) << "\":";
                            first = false;
                            os << x;
                        }
                        os << '}';
                    }
                    break;
                }
                return os;
            }
        };
        namespace detail {
        }

        inline bool operator == (const rvalue& l, const std::string& r)
        {
            return l.s() == r;
        }

        inline bool operator == (const std::string& l, const rvalue& r)
        {
            return l == r.s();
        }

        inline bool operator != (const rvalue& l, const std::string& r)
        {
            return l.s() != r;
        }

        inline bool operator != (const std::string& l, const rvalue& r)
        {
            return l != r.s();
        }

        inline bool operator == (const rvalue& l, double r)
        {
            return l.d() == r;
        }

        inline bool operator == (double l, const rvalue& r)
        {
            return l == r.d();
        }

        inline bool operator != (const rvalue& l, double r)
        {
            return l.d() != r;
        }

        inline bool operator != (double l, const rvalue& r)
        {
            return l != r.d();
        }


        inline rvalue load_nocopy_internal(char* data, size_t size)
        {

            struct Parser
            {
                Parser(char* data, size_t )
                    : data(data)
                {
                }

                bool consume(char c)
                {
                    if (__builtin_expect(*data != c, 0))
                        return false;
                    data++;
                    return true;
                }

                void ws_skip()
                {
                    while(*data == ' ' || *data == '\t' || *data == '\r' || *data == '\n') ++data;
                };

                rvalue decode_string()
                {
                    if (__builtin_expect(!consume('"'), 0))
                        return {};
                    char* start = data;
                    uint8_t has_escaping = 0;
                    while(1)
                    {
                        if (__builtin_expect(*data != '"' && *data != '\\' && *data != '\0', 1))
                        {
                            data ++;
                        }
                        else if (*data == '"')
                        {
                            *data = 0;
                            *(start-1) = has_escaping;
                            data++;
                            return {type::String, start, data-1};
                        }
                        else if (*data == '\\')
                        {
                            has_escaping = 1;
                            data++;
                            switch(*data)
                            {
                                case 'u':
                                    {
                                        auto check = [](char c)
                                        {
                                            return
                                                ('0' <= c && c <= '9') ||
                                                ('a' <= c && c <= 'f') ||
                                                ('A' <= c && c <= 'F');
                                        };
                                        if (!(check(*(data+1)) &&
                                            check(*(data+2)) &&
                                            check(*(data+3)) &&
                                            check(*(data+4))))
                                            return {};
                                    }
                                    data += 5;
                                    break;
                                case '"':
                                case '\\':
                                case '/':
                                case 'b':
                                case 'f':
                                case 'n':
                                case 'r':
                                case 't':
                                    data ++;
                                    break;
                                default:
                                    return {};
                            }
                        }
                        else
                            return {};
                    }
                    return {};
                }

                rvalue decode_list()
                {
                    rvalue ret(type::List);
                    if (__builtin_expect(!consume('['), 0))
                    {
                        ret.set_error();
                        return ret;
                    }
                    ws_skip();
                    if (__builtin_expect(*data == ']', 0))
                    {
                        data++;
                        return ret;
                    }

                    while(1)
                    {
                        auto v = decode_value();
                        if (__builtin_expect(!v, 0))
                        {
                            ret.set_error();
                            break;
                        }
                        ws_skip();
                        ret.emplace_back(std::move(v));
                        if (*data == ']')
                        {
                            data++;
                            break;
                        }
                        if (__builtin_expect(!consume(','), 0))
                        {
                            ret.set_error();
                            break;
                        }
                        ws_skip();
                    }
                    return ret;
                }

                rvalue decode_number()
                {
                    char* start = data;

                    enum NumberParsingState
                    {
                        Minus,
                        AfterMinus,
                        ZeroFirst,
                        Digits,
                        DigitsAfterPoints,
                        E,
                        DigitsAfterE,
                        Invalid,
                    } state{Minus};
                    while(__builtin_expect(state != Invalid, 1))
                    {
                        switch(*data)
                        {
                            case '0':
                                state = (NumberParsingState)"\2\2\7\3\4\6\6"[state];

                                break;
                            case '1': case '2': case '3':
                            case '4': case '5': case '6':
                            case '7': case '8': case '9':
                                state = (NumberParsingState)"\3\3\7\3\4\6\6"[state];
                                while(*(data+1) >= '0' && *(data+1) <= '9') data++;

                                break;
                            case '.':
                                state = (NumberParsingState)"\7\7\4\4\7\7\7"[state];

                                break;
                            case '-':
                                state = (NumberParsingState)"\1\7\7\7\7\6\7"[state];

                                break;
                            case '+':
                                state = (NumberParsingState)"\7\7\7\7\7\6\7"[state];






                                break;
                            case 'e': case 'E':
                                state = (NumberParsingState)"\7\7\7\5\5\7\7"[state];







                                break;
                            default:
                                if (__builtin_expect(state == NumberParsingState::ZeroFirst || state == NumberParsingState::Digits || state == NumberParsingState::DigitsAfterPoints || state == NumberParsingState::DigitsAfterE, 1)


                                                                                  )
                                    return {type::Number, start, data};
                                else
                                    return {};
                        }
                        data++;
                    }

                    return {};
                }

                rvalue decode_value()
                {
                    switch(*data)
                    {
                        case '[':
                            return decode_list();
                        case '{':
                            return decode_object();
                        case '"':
                            return decode_string();
                        case 't':
                            if (
                                    data[1] == 'r' &&
                                    data[2] == 'u' &&
                                    data[3] == 'e')
                            {
                                data += 4;
                                return {type::True};
                            }
                            else
                                return {};
                        case 'f':
                            if (
                                    data[1] == 'a' &&
                                    data[2] == 'l' &&
                                    data[3] == 's' &&
                                    data[4] == 'e')
                            {
                                data += 5;
                                return {type::False};
                            }
                            else
                                return {};
                        case 'n':
                            if (
                                    data[1] == 'u' &&
                                    data[2] == 'l' &&
                                    data[3] == 'l')
                            {
                                data += 4;
                                return {type::Null};
                            }
                            else
                                return {};




                        default:
                            return decode_number();
                    }
                    return {};
                }

                rvalue decode_object()
                {
                    rvalue ret(type::Object);
                    if (__builtin_expect(!consume('{'), 0))
                    {
                        ret.set_error();
                        return ret;
                    }

                    ws_skip();

                    if (__builtin_expect(*data == '}', 0))
                    {
                        data++;
                        return ret;
                    }

                    while(1)
                    {
                        auto t = decode_string();
                        if (__builtin_expect(!t, 0))
                        {
                            ret.set_error();
                            break;
                        }

                        ws_skip();
                        if (__builtin_expect(!consume(':'), 0))
                        {
                            ret.set_error();
                            break;
                        }


                        auto key = t.s();

                        ws_skip();
                        auto v = decode_value();
                        if (__builtin_expect(!v, 0))
                        {
                            ret.set_error();
                            break;
                        }
                        ws_skip();

                        v.key_ = std::move(key);
                        ret.emplace_back(std::move(v));
                        if (__builtin_expect(*data == '}', 0))
                        {
                            data++;
                            break;
                        }
                        if (__builtin_expect(!consume(','), 0))
                        {
                            ret.set_error();
                            break;
                        }
                        ws_skip();
                    }
                    return ret;
                }

                rvalue parse()
                {
                    ws_skip();
                    auto ret = decode_value();
                    ws_skip();
                    if (ret && *data != '\0')
                        ret.set_error();
                    return ret;
                }

                char* data;
            };
            return Parser(data, size).parse();
        }
        inline rvalue load(const char* data, size_t size)
        {
            char* s = new char[size+1];
            memcpy(s, data, size);
            s[size] = 0;
            auto ret = load_nocopy_internal(s, size);
            if (ret)
                ret.key_.force(s, size);
            else
                delete[] s;
            return ret;
        }

        inline rvalue load(const char* data)
        {
            return load(data, strlen(data));
        }

        inline rvalue load(const std::string& str)
        {
            return load(str.data(), str.size());
        }

        class wvalue
        {
            friend class crow::mustache::template_t;
        public:
            type t() const { return t_; }
        private:
            type t_{type::Null};
            num_type nt{num_type::Null};
            union {
              double d;
              int64_t si;
              uint64_t ui {};
            } num;
            std::string s;
            std::unique_ptr<std::vector<wvalue>> l;
            std::unique_ptr<std::unordered_map<std::string, wvalue>> o;
        public:

            wvalue() {}

            wvalue(const rvalue& r)
            {
                t_ = r.t();
                switch(r.t())
                {
                    case type::Null:
                    case type::False:
                    case type::True:
                        return;
                    case type::Number:
                        nt = r.nt();
                        if (nt == num_type::Floating_point)
                          num.d = r.d();
                        else if (nt == num_type::Signed_integer)
                          num.si = r.i();
                        else
                          num.ui = r.u();
                        return;
                    case type::String:
                        s = r.s();
                        return;
                    case type::List:
                        l = std::unique_ptr<std::vector<wvalue>>(new std::vector<wvalue>{});
                        l->reserve(r.size());
                        for(auto it = r.begin(); it != r.end(); ++it)
                            l->emplace_back(*it);
                        return;
                    case type::Object:
                        o = std::unique_ptr<
                                    std::unordered_map<std::string, wvalue>
                                >(
                                new std::unordered_map<std::string, wvalue>{});
                        for(auto it = r.begin(); it != r.end(); ++it)
                            o->emplace(it->key(), *it);
                        return;
                }
            }

            wvalue(wvalue&& r)
            {
                *this = std::move(r);
            }

            wvalue& operator = (wvalue&& r)
            {
                t_ = r.t_;
                num = r.num;
                s = std::move(r.s);
                l = std::move(r.l);
                o = std::move(r.o);
                return *this;
            }

            void clear()
            {
                reset();
            }

            void reset()
            {
                t_ = type::Null;
                l.reset();
                o.reset();
            }

            wvalue& operator = (std::nullptr_t)
            {
                reset();
                return *this;
            }
            wvalue& operator = (bool value)
            {
                reset();
                if (value)
                    t_ = type::True;
                else
                    t_ = type::False;
                return *this;
            }

            wvalue& operator = (double value)
            {
                reset();
                t_ = type::Number;
                num.d = value;
                nt = num_type::Floating_point;
                return *this;
            }

            wvalue& operator = (unsigned short value)
            {
                reset();
                t_ = type::Number;
                num.ui = value;
                nt = num_type::Unsigned_integer;
                return *this;
            }

            wvalue& operator = (short value)
            {
                reset();
                t_ = type::Number;
                num.si = value;
                nt = num_type::Signed_integer;
                return *this;
            }

            wvalue& operator = (long long value)
            {
                reset();
                t_ = type::Number;
                num.si = value;
                nt = num_type::Signed_integer;
                return *this;
            }

            wvalue& operator = (long value)
            {
                reset();
                t_ = type::Number;
                num.si = value;
                nt = num_type::Signed_integer;
                return *this;
            }

            wvalue& operator = (int value)
            {
                reset();
                t_ = type::Number;
                num.si = value;
                nt = num_type::Signed_integer;
                return *this;
            }

            wvalue& operator = (unsigned long long value)
            {
                reset();
                t_ = type::Number;
                num.ui = value;
                nt = num_type::Unsigned_integer;
                return *this;
            }

            wvalue& operator = (unsigned long value)
            {
                reset();
                t_ = type::Number;
                num.ui = value;
                nt = num_type::Unsigned_integer;
                return *this;
            }

            wvalue& operator = (unsigned int value)
            {
                reset();
                t_ = type::Number;
                num.ui = value;
                nt = num_type::Unsigned_integer;
                return *this;
            }

            wvalue& operator=(const char* str)
            {
                reset();
                t_ = type::String;
                s = str;
                return *this;
            }

            wvalue& operator=(const std::string& str)
            {
                reset();
                t_ = type::String;
                s = str;
                return *this;
            }

            wvalue& operator=(std::vector<wvalue>&& v)
            {
                if (t_ != type::List)
                    reset();
                t_ = type::List;
                if (!l)
                    l = std::unique_ptr<std::vector<wvalue>>(new std::vector<wvalue>{});
                l->clear();
                l->resize(v.size());
                size_t idx = 0;
                for(auto& x:v)
                {
                    (*l)[idx++] = std::move(x);
                }
                return *this;
            }

            template <typename T>
            wvalue& operator=(const std::vector<T>& v)
            {
                if (t_ != type::List)
                    reset();
                t_ = type::List;
                if (!l)
                    l = std::unique_ptr<std::vector<wvalue>>(new std::vector<wvalue>{});
                l->clear();
                l->resize(v.size());
                size_t idx = 0;
                for(auto& x:v)
                {
                    (*l)[idx++] = x;
                }
                return *this;
            }

            wvalue& operator[](unsigned index)
            {
                if (t_ != type::List)
                    reset();
                t_ = type::List;
                if (!l)
                    l = std::unique_ptr<std::vector<wvalue>>(new std::vector<wvalue>{});
                if (l->size() < index+1)
                    l->resize(index+1);
                return (*l)[index];
            }

            int count(const std::string& str)
            {
                if (t_ != type::Object)
                    return 0;
                if (!o)
                    return 0;
                return o->count(str);
            }

            wvalue& operator[](const std::string& str)
            {
                if (t_ != type::Object)
                    reset();
                t_ = type::Object;
                if (!o)
                    o = std::unique_ptr<
                                std::unordered_map<std::string, wvalue>
                            >(
                            new std::unordered_map<std::string, wvalue>{});
                return (*o)[str];
            }

            std::vector<std::string> keys() const
            {
                if (t_ != type::Object)
                    return {};
                std::vector<std::string> result;
                for (auto& kv:*o)
                {
                    result.push_back(kv.first);
                }
                return result;
            }

            size_t estimate_length() const
            {
                switch(t_)
                {
                    case type::Null: return 4;
                    case type::False: return 5;
                    case type::True: return 4;
                    case type::Number: return 30;
                    case type::String: return 2+s.size()+s.size()/2;
                    case type::List:
                        {
                            size_t sum{};
                            if (l)
                            {
                                for(auto& x:*l)
                                {
                                    sum += 1;
                                    sum += x.estimate_length();
                                }
                            }
                            return sum+2;
                        }
                    case type::Object:
                        {
                            size_t sum{};
                            if (o)
                            {
                                for(auto& kv:*o)
                                {
                                    sum += 2;
                                    sum += 2+kv.first.size()+kv.first.size()/2;
                                    sum += kv.second.estimate_length();
                                }
                            }
                            return sum+2;
                        }
                }
                return 1;
            }

            friend void dump_internal(const wvalue& v, std::string& out);
            friend std::string dump(const wvalue& v);
        };

        inline void dump_string(const std::string& str, std::string& out)
        {
            out.push_back('"');
            escape(str, out);
            out.push_back('"');
        }
        inline void dump_internal(const wvalue& v, std::string& out)
        {
            switch(v.t_)
            {
                case type::Null: out += "null"; break;
                case type::False: out += "false"; break;
                case type::True: out += "true"; break;
                case type::Number:
                    {
                        if (v.nt == num_type::Floating_point)
                        {





                            char outbuf[128];
                            sprintf((outbuf), ("%g"), (v.num.d));
                            out += outbuf;

                        }
                        else if (v.nt == num_type::Signed_integer)
                        {
                            out += std::to_string(v.num.si);
                        }
                        else
                        {
                            out += std::to_string(v.num.ui);
                        }
                    }
                    break;
                case type::String: dump_string(v.s, out); break;
                case type::List:
                     {
                         out.push_back('[');
                         if (v.l)
                         {
                             bool first = true;
                             for(auto& x:*v.l)
                             {
                                 if (!first)
                                 {
                                     out.push_back(',');
                                 }
                                 first = false;
                                 dump_internal(x, out);
                             }
                         }
                         out.push_back(']');
                     }
                     break;
                case type::Object:
                     {
                         out.push_back('{');
                         if (v.o)
                         {
                             bool first = true;
                             for(auto& kv:*v.o)
                             {
                                 if (!first)
                                 {
                                     out.push_back(',');
                                 }
                                 first = false;
                                 dump_string(kv.first, out);
                                 out.push_back(':');
                                 dump_internal(kv.second, out);
                             }
                         }
                         out.push_back('}');
                     }
                     break;
            }
        }

        inline std::string dump(const wvalue& v)
        {
            std::string ret;
            ret.reserve(v.estimate_length());
            dump_internal(v, ret);
            return ret;
        }




    }
}


       






namespace crow
{
    namespace mustache
    {
        using context = json::wvalue;

        template_t load(const std::string& filename);

        class invalid_template_exception : public std::exception
        {
            public:
            invalid_template_exception(const std::string& msg)
                : msg("crow::mustache error: " + msg)
            {
            }
            virtual const char* what() const throw()
            {
                return msg.c_str();
            }
            std::string msg;
        };

        enum class ActionType
        {
            Ignore,
            Tag,
            UnescapeTag,
            OpenBlock,
            CloseBlock,
            ElseBlock,
            Partial,
        };

        struct Action
        {
            int start;
            int end;
            int pos;
            ActionType t;
            Action(ActionType t, int start, int end, int pos = 0)
                : start(start), end(end), pos(pos), t(t)
            {}
        };

        class template_t
        {
        public:
            template_t(std::string body)
                : body_(std::move(body))
            {

                parse();
            }

        private:
            std::string tag_name(const Action& action)
            {
                return body_.substr(action.start, action.end - action.start);
            }
            auto find_context(const std::string& name, const std::vector<context*>& stack)->std::pair<bool, context&>
            {
                if (name == ".")
                {
                    return {true, *stack.back()};
                }
                int dotPosition = name.find(".");
                if (dotPosition == (int)name.npos)
                {
                    for(auto it = stack.rbegin(); it != stack.rend(); ++it)
                    {
                        if ((*it)->t() == json::type::Object)
                        {
                            if ((*it)->count(name))
                                return {true, (**it)[name]};
                        }
                    }
                }
                else
                {
                    std::vector<int> dotPositions;
                    dotPositions.push_back(-1);
                    while(dotPosition != (int)name.npos)
                    {
                        dotPositions.push_back(dotPosition);
                        dotPosition = name.find(".", dotPosition+1);
                    }
                    dotPositions.push_back(name.size());
                    std::vector<std::string> names;
                    names.reserve(dotPositions.size()-1);
                    for(int i = 1; i < (int)dotPositions.size(); i ++)
                        names.emplace_back(name.substr(dotPositions[i-1]+1, dotPositions[i]-dotPositions[i-1]-1));

                    for(auto it = stack.rbegin(); it != stack.rend(); ++it)
                    {
                        context* view = *it;
                        bool found = true;
                        for(auto jt = names.begin(); jt != names.end(); ++jt)
                        {
                            if (view->t() == json::type::Object &&
                                view->count(*jt))
                            {
                                view = &(*view)[*jt];
                            }
                            else
                            {
                                found = false;
                                break;
                            }
                        }
                        if (found)
                            return {true, *view};
                    }

                }

                static json::wvalue empty_str;
                empty_str = "";
                return {false, empty_str};
            }

            void escape(const std::string& in, std::string& out)
            {
                out.reserve(out.size() + in.size());
                for(auto it = in.begin(); it != in.end(); ++it)
                {
                    switch(*it)
                    {
                        case '&': out += "&amp;"; break;
                        case '<': out += "&lt;"; break;
                        case '>': out += "&gt;"; break;
                        case '"': out += "&quot;"; break;
                        case '\'': out += "&#39;"; break;
                        case '/': out += "&#x2F;"; break;
                        default: out += *it; break;
                    }
                }
            }

            void render_internal(int actionBegin, int actionEnd, std::vector<context*>& stack, std::string& out, int indent)
            {
                int current = actionBegin;

                if (indent)
                    out.insert(out.size(), indent, ' ');

                while(current < actionEnd)
                {
                    auto& fragment = fragments_[current];
                    auto& action = actions_[current];
                    render_fragment(fragment, indent, out);
                    switch(action.t)
                    {
                        case ActionType::Ignore:

                            break;
                        case ActionType::Partial:
                            {
                                std::string partial_name = tag_name(action);
                                auto partial_templ = load(partial_name);
                                int partial_indent = action.pos;
                                partial_templ.render_internal(0, partial_templ.fragments_.size()-1, stack, out, partial_indent?indent+partial_indent:0);
                            }
                            break;
                        case ActionType::UnescapeTag:
                        case ActionType::Tag:
                            {
                                auto optional_ctx = find_context(tag_name(action), stack);
                                auto& ctx = optional_ctx.second;
                                switch(ctx.t())
                                {
                                    case json::type::Number:
                                        out += json::dump(ctx);
                                        break;
                                    case json::type::String:
                                        if (action.t == ActionType::Tag)
                                            escape(ctx.s, out);
                                        else
                                            out += ctx.s;
                                        break;
                                    default:
                                        throw std::runtime_error("not implemented tag type" + boost::lexical_cast<std::string>((int)ctx.t()));
                                }
                            }
                            break;
                        case ActionType::ElseBlock:
                            {
                                static context nullContext;
                                auto optional_ctx = find_context(tag_name(action), stack);
                                if (!optional_ctx.first)
                                {
                                    stack.emplace_back(&nullContext);
                                    break;
                                }

                                auto& ctx = optional_ctx.second;
                                switch(ctx.t())
                                {
                                    case json::type::List:
                                        if (ctx.l && !ctx.l->empty())
                                            current = action.pos;
                                        else
                                            stack.emplace_back(&nullContext);
                                        break;
                                    case json::type::False:
                                    case json::type::Null:
                                        stack.emplace_back(&nullContext);
                                        break;
                                    default:
                                        current = action.pos;
                                        break;
                                }
                                break;
                            }
                        case ActionType::OpenBlock:
                            {
                                auto optional_ctx = find_context(tag_name(action), stack);
                                if (!optional_ctx.first)
                                {
                                    current = action.pos;
                                    break;
                                }

                                auto& ctx = optional_ctx.second;
                                switch(ctx.t())
                                {
                                    case json::type::List:
                                        if (ctx.l)
                                            for(auto it = ctx.l->begin(); it != ctx.l->end(); ++it)
                                            {
                                                stack.push_back(&*it);
                                                render_internal(current+1, action.pos, stack, out, indent);
                                                stack.pop_back();
                                            }
                                        current = action.pos;
                                        break;
                                    case json::type::Number:
                                    case json::type::String:
                                    case json::type::Object:
                                    case json::type::True:
                                        stack.push_back(&ctx);
                                        break;
                                    case json::type::False:
                                    case json::type::Null:
                                        current = action.pos;
                                        break;
                                    default:
                                        throw std::runtime_error("{{#: not implemented context type: " + boost::lexical_cast<std::string>((int)ctx.t()));
                                        break;
                                }
                                break;
                            }
                        case ActionType::CloseBlock:
                            stack.pop_back();
                            break;
                        default:
                            throw std::runtime_error("not implemented " + boost::lexical_cast<std::string>((int)action.t));
                    }
                    current++;
                }
                auto& fragment = fragments_[actionEnd];
                render_fragment(fragment, indent, out);
            }
            void render_fragment(const std::pair<int, int> fragment, int indent, std::string& out)
            {
                if (indent)
                {
                    for(int i = fragment.first; i < fragment.second; i ++)
                    {
                        out += body_[i];
                        if (body_[i] == '\n' && i+1 != (int)body_.size())
                            out.insert(out.size(), indent, ' ');
                    }
                }
                else
                    out.insert(out.size(), body_, fragment.first, fragment.second-fragment.first);
            }
        public:
            std::string render()
            {
                context empty_ctx;
                std::vector<context*> stack;
                stack.emplace_back(&empty_ctx);

                std::string ret;
                render_internal(0, fragments_.size()-1, stack, ret, 0);
                return ret;
            }
            std::string render(context& ctx)
            {
                std::vector<context*> stack;
                stack.emplace_back(&ctx);

                std::string ret;
                render_internal(0, fragments_.size()-1, stack, ret, 0);
                return ret;
            }

        private:

            void parse()
            {
                std::string tag_open = "{{";
                std::string tag_close = "}}";

                std::vector<int> blockPositions;

                size_t current = 0;
                while(1)
                {
                    size_t idx = body_.find(tag_open, current);
                    if (idx == body_.npos)
                    {
                        fragments_.emplace_back(current, body_.size());
                        actions_.emplace_back(ActionType::Ignore, 0, 0);
                        break;
                    }
                    fragments_.emplace_back(current, idx);

                    idx += tag_open.size();
                    size_t endIdx = body_.find(tag_close, idx);
                    if (endIdx == idx)
                    {
                        throw invalid_template_exception("empty tag is not allowed");
                    }
                    if (endIdx == body_.npos)
                    {

                        throw invalid_template_exception("not matched opening tag");
                    }
                    current = endIdx + tag_close.size();
                    switch(body_[idx])
                    {
                        case '#':
                            idx++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            blockPositions.emplace_back(actions_.size());
                            actions_.emplace_back(ActionType::OpenBlock, idx, endIdx);
                            break;
                        case '/':
                            idx++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            {
                                auto& matched = actions_[blockPositions.back()];
                                if (body_.compare(idx, endIdx-idx,
                                        body_, matched.start, matched.end - matched.start) != 0)
                                {
                                    throw invalid_template_exception("not matched {{# {{/ pair: " +
                                        body_.substr(matched.start, matched.end - matched.start) + ", " +
                                        body_.substr(idx, endIdx-idx));
                                }
                                matched.pos = actions_.size();
                            }
                            actions_.emplace_back(ActionType::CloseBlock, idx, endIdx, blockPositions.back());
                            blockPositions.pop_back();
                            break;
                        case '^':
                            idx++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            blockPositions.emplace_back(actions_.size());
                            actions_.emplace_back(ActionType::ElseBlock, idx, endIdx);
                            break;
                        case '!':

                            actions_.emplace_back(ActionType::Ignore, idx+1, endIdx);
                            break;
                        case '>':
                            idx++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            actions_.emplace_back(ActionType::Partial, idx, endIdx);
                            break;
                        case '{':
                            if (tag_open != "{{" || tag_close != "}}")
                                throw invalid_template_exception("cannot use triple mustache when delimiter changed");

                            idx ++;
                            if (body_[endIdx+2] != '}')
                            {
                                throw invalid_template_exception("{{{: }}} not matched");
                            }
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            actions_.emplace_back(ActionType::UnescapeTag, idx, endIdx);
                            current++;
                            break;
                        case '&':
                            idx ++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            actions_.emplace_back(ActionType::UnescapeTag, idx, endIdx);
                            break;
                        case '=':

                            idx ++;
                            actions_.emplace_back(ActionType::Ignore, idx, endIdx);
                            endIdx --;
                            if (body_[endIdx] != '=')
                                throw invalid_template_exception("{{=: not matching = tag: "+body_.substr(idx, endIdx-idx));
                            endIdx --;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx] == ' ') endIdx--;
                            endIdx++;
                            {
                                bool succeeded = false;
                                for(size_t i = idx; i < endIdx; i++)
                                {
                                    if (body_[i] == ' ')
                                    {
                                        tag_open = body_.substr(idx, i-idx);
                                        while(body_[i] == ' ') i++;
                                        tag_close = body_.substr(i, endIdx-i);
                                        if (tag_open.empty())
                                            throw invalid_template_exception("{{=: empty open tag");
                                        if (tag_close.empty())
                                            throw invalid_template_exception("{{=: empty close tag");

                                        if (tag_close.find(" ") != tag_close.npos)
                                            throw invalid_template_exception("{{=: invalid open/close tag: "+tag_open+" " + tag_close);
                                        succeeded = true;
                                        break;
                                    }
                                }
                                if (!succeeded)
                                    throw invalid_template_exception("{{=: cannot find space between new open/close tags");
                            }
                            break;
                        default:

                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            actions_.emplace_back(ActionType::Tag, idx, endIdx);
                            break;
                    }
                }


                for(int i = actions_.size()-2; i >= 0; i --)
                {
                    if (actions_[i].t == ActionType::Tag || actions_[i].t == ActionType::UnescapeTag)
                        continue;
                    auto& fragment_before = fragments_[i];
                    auto& fragment_after = fragments_[i+1];
                    bool is_last_action = i == (int)actions_.size()-2;
                    bool all_space_before = true;
                    int j, k;
                    for(j = fragment_before.second-1;j >= fragment_before.first;j--)
                    {
                        if (body_[j] != ' ')
                        {
                            all_space_before = false;
                            break;
                        }
                    }
                    if (all_space_before && i > 0)
                        continue;
                    if (!all_space_before && body_[j] != '\n')
                        continue;
                    bool all_space_after = true;
                    for(k = fragment_after.first; k < (int)body_.size() && k < fragment_after.second; k ++)
                    {
                        if (body_[k] != ' ')
                        {
                            all_space_after = false;
                            break;
                        }
                    }
                    if (all_space_after && !is_last_action)
                        continue;
                    if (!all_space_after &&
                            !(
                                body_[k] == '\n'
                            ||
                                (body_[k] == '\r' &&
                                k + 1 < (int)body_.size() &&
                                body_[k+1] == '\n')))
                        continue;
                    if (actions_[i].t == ActionType::Partial)
                    {
                        actions_[i].pos = fragment_before.second - j - 1;
                    }
                    fragment_before.second = j+1;
                    if (!all_space_after)
                    {
                        if (body_[k] == '\n')
                            k++;
                        else
                            k += 2;
                        fragment_after.first = k;
                    }
                }
            }

            std::vector<std::pair<int,int>> fragments_;
            std::vector<Action> actions_;
            std::string body_;
        };

        inline template_t compile(const std::string& body)
        {
            return template_t(body);
        }
        namespace detail
        {
            inline std::string& get_template_base_directory_ref()
            {
                static std::string template_base_directory = "templates";
                return template_base_directory;
            }
        }

        inline std::string default_loader(const std::string& filename)
        {
            std::string path = detail::get_template_base_directory_ref();
            if (!(path.back() == '/' || path.back() == '\\'))
                path += '/';
            path += filename;
            std::ifstream inf(path);
            if (!inf)
                return {};
            return {std::istreambuf_iterator<char>(inf), std::istreambuf_iterator<char>()};
        }

        namespace detail
        {
            inline std::function<std::string (std::string)>& get_loader_ref()
            {
                static std::function<std::string (std::string)> loader = default_loader;
                return loader;
            }
        }

        inline void set_base(const std::string& path)
        {
            auto& base = detail::get_template_base_directory_ref();
            base = path;
            if (base.back() != '\\' &&
                base.back() != '/')
            {
                base += '/';
            }
        }

        inline void set_loader(std::function<std::string(std::string)> loader)
        {
            detail::get_loader_ref() = std::move(loader);
        }

        inline std::string load_text(const std::string& filename)
        {
            return detail::get_loader_ref()(filename);
        }

        inline template_t load(const std::string& filename)
        {
            return compile(detail::get_loader_ref()(filename));
        }
    }
}


       










namespace crow
{
    enum class LogLevel
    {

        DEBUG = 0,
        INFO,
        WARNING,
        ERROR,
        CRITICAL,


        Debug = 0,
        Info,
        Warning,
        Error,
        Critical,
    };

    class ILogHandler {
        public:
            virtual void log(std::string message, LogLevel level) = 0;
    };

    class CerrLogHandler : public ILogHandler {
        public:
            void log(std::string message, LogLevel ) override {
                std::cerr << message;
            }
    };

    class logger {

        private:

            static std::string timestamp()
            {
                char date[32];
                time_t t = time(0);

                tm my_tm;




                gmtime_r(&t, &my_tm);


                size_t sz = strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &my_tm);
                return std::string(date, date+sz);
            }

        public:


            logger(std::string prefix, LogLevel level) : level_(level) {

                    stringstream_ << "(" << timestamp() << ") [" << prefix << "] ";


            }
            ~logger() {

                if(level_ >= get_current_log_level()) {
                    stringstream_ << std::endl;
                    get_handler_ref()->log(stringstream_.str(), level_);
                }

            }


            template <typename T>
            logger& operator<<(T const &value) {


                if(level_ >= get_current_log_level()) {
                    stringstream_ << value;
                }

                return *this;
            }


            static void setLogLevel(LogLevel level) {
                get_log_level_ref() = level;
            }

            static void setHandler(ILogHandler* handler) {
                get_handler_ref() = handler;
            }

            static LogLevel get_current_log_level() {
                return get_log_level_ref();
            }

        private:

            static LogLevel& get_log_level_ref()
            {
                static LogLevel current_level = (LogLevel)1;
                return current_level;
            }
            static ILogHandler*& get_handler_ref()
            {
                static CerrLogHandler default_handler;
                static ILogHandler* current_handler = &default_handler;
                return current_handler;
            }


            std::ostringstream stringstream_;
            LogLevel level_;
    };
}


       









namespace crow
{
    namespace detail
    {

        class dumb_timer_queue
        {
        public:
            using key = std::pair<dumb_timer_queue*, int>;

            void cancel(key& k)
            {
                auto self = k.first;
                k.first = nullptr;
                if (!self)
                    return;

                unsigned int index = (unsigned int)(k.second - self->step_);
                if (index < self->dq_.size())
                    self->dq_[index].second = nullptr;
            }

            key add(std::function<void()> f)
            {
                dq_.emplace_back(std::chrono::steady_clock::now(), std::move(f));
                int ret = step_+dq_.size()-1;

                if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "timer add inside: " << this << ' ' << ret ;
                return {this, ret};
            }

            void process()
            {
                if (!io_service_)
                    return;

                auto now = std::chrono::steady_clock::now();
                while(!dq_.empty())
                {
                    auto& x = dq_.front();
                    if (now - x.first < std::chrono::seconds(tick))
                        break;
                    if (x.second)
                    {
                        if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "timer call: " << this << ' ' << step_;

                        x.second();
                    }
                    dq_.pop_front();
                    step_++;
                }
            }

            void set_io_service(boost::asio::io_service& io_service)
            {
                io_service_ = &io_service;
            }

            dumb_timer_queue() noexcept
            {
            }

        private:

            int tick{5};
            boost::asio::io_service* io_service_{};
            std::deque<std::pair<decltype(std::chrono::steady_clock::now()), std::function<void()>>> dq_;
            int step_{};
        };
    }
}


       











namespace crow
{
    namespace black_magic
    {

        struct OutOfRange
        {
            OutOfRange(unsigned , unsigned ) {}
        };
        constexpr unsigned requires_in_range( unsigned i, unsigned len )
        {
            return i >= len ? throw OutOfRange(i, len) : i;
        }

        class const_str
        {
            const char * const begin_;
            unsigned size_;

            public:
            template< unsigned N >
                constexpr const_str( const char(&arr)[N] ) : begin_(arr), size_(N - 1) {
                    static_assert( N >= 1, "not a string literal");
                }
            constexpr char operator[]( unsigned i ) const {
                return requires_in_range(i, size_), begin_[i];
            }

            constexpr operator const char *() const {
                return begin_;
            }

            constexpr const char* begin() const { return begin_; }
            constexpr const char* end() const { return begin_ + size_; }

            constexpr unsigned size() const {
                return size_;
            }
        };

        constexpr unsigned find_closing_tag(const_str s, unsigned p)
        {
            return s[p] == '>' ? p : find_closing_tag(s, p+1);
        }

        constexpr bool is_valid(const_str s, unsigned i = 0, int f = 0)
        {
            return
                i == s.size()
                    ? f == 0 :
                f < 0 || f >= 2
                    ? false :
                s[i] == '<'
                    ? is_valid(s, i+1, f+1) :
                s[i] == '>'
                    ? is_valid(s, i+1, f-1) :
                is_valid(s, i+1, f);
        }

        constexpr bool is_equ_p(const char* a, const char* b, unsigned n)
        {
            return
                *a == 0 && *b == 0 && n == 0
                    ? true :
                (*a == 0 || *b == 0)
                    ? false :
                n == 0
                    ? true :
                *a != *b
                    ? false :
                is_equ_p(a+1, b+1, n-1);
        }

        constexpr bool is_equ_n(const_str a, unsigned ai, const_str b, unsigned bi, unsigned n)
        {
            return
                ai + n > a.size() || bi + n > b.size()
                    ? false :
                n == 0
                    ? true :
                a[ai] != b[bi]
                    ? false :
                is_equ_n(a,ai+1,b,bi+1,n-1);
        }

        constexpr bool is_int(const_str s, unsigned i)
        {
            return is_equ_n(s, i, "<int>", 0, 5);
        }

        constexpr bool is_uint(const_str s, unsigned i)
        {
            return is_equ_n(s, i, "<uint>", 0, 6);
        }

        constexpr bool is_float(const_str s, unsigned i)
        {
            return is_equ_n(s, i, "<float>", 0, 7) ||
                is_equ_n(s, i, "<double>", 0, 8);
        }

        constexpr bool is_str(const_str s, unsigned i)
        {
            return is_equ_n(s, i, "<str>", 0, 5) ||
                is_equ_n(s, i, "<string>", 0, 8);
        }

        constexpr bool is_path(const_str s, unsigned i)
        {
            return is_equ_n(s, i, "<path>", 0, 6);
        }

        template <typename T>
        struct parameter_tag
        {
            static const int value = 0;
        };






        template <> struct parameter_tag<int> { static const int value = 1; };
        template <> struct parameter_tag<char> { static const int value = 1; };
        template <> struct parameter_tag<short> { static const int value = 1; };
        template <> struct parameter_tag<long> { static const int value = 1; };
        template <> struct parameter_tag<long long> { static const int value = 1; };
        template <> struct parameter_tag<unsigned int> { static const int value = 2; };
        template <> struct parameter_tag<unsigned char> { static const int value = 2; };
        template <> struct parameter_tag<unsigned short> { static const int value = 2; };
        template <> struct parameter_tag<unsigned long> { static const int value = 2; };
        template <> struct parameter_tag<unsigned long long> { static const int value = 2; };
        template <> struct parameter_tag<double> { static const int value = 3; };
        template <> struct parameter_tag<std::string> { static const int value = 4; };

        template <typename ... Args>
        struct compute_parameter_tag_from_args_list;

        template <>
        struct compute_parameter_tag_from_args_list<>
        {
            static const int value = 0;
        };

        template <typename Arg, typename ... Args>
        struct compute_parameter_tag_from_args_list<Arg, Args...>
        {
            static const int sub_value =
                compute_parameter_tag_from_args_list<Args...>::value;
            static const int value =
                parameter_tag<typename std::decay<Arg>::type>::value
                ? sub_value* 6 + parameter_tag<typename std::decay<Arg>::type>::value
                : sub_value;
        };

        static inline bool is_parameter_tag_compatible(uint64_t a, uint64_t b)
        {
            if (a == 0)
                return b == 0;
            if (b == 0)
                return a == 0;
            int sa = a%6;
            int sb = a%6;
            if (sa == 5) sa = 4;
            if (sb == 5) sb = 4;
            if (sa != sb)
                return false;
            return is_parameter_tag_compatible(a/6, b/6);
        }

        static inline unsigned find_closing_tag_runtime(const char* s, unsigned p)
        {
            return
                s[p] == 0
                ? throw std::runtime_error("unmatched tag <") :
                s[p] == '>'
                ? p : find_closing_tag_runtime(s, p + 1);
        }

        static inline uint64_t get_parameter_tag_runtime(const char* s, unsigned p = 0)
        {
            return
                s[p] == 0
                    ? 0 :
                s[p] == '<' ? (
                    std::strncmp(s+p, "<int>", 5) == 0
                        ? get_parameter_tag_runtime(s, find_closing_tag_runtime(s, p)) * 6 + 1 :
                    std::strncmp(s+p, "<uint>", 6) == 0
                        ? get_parameter_tag_runtime(s, find_closing_tag_runtime(s, p)) * 6 + 2 :
                    (std::strncmp(s+p, "<float>", 7) == 0 ||
                    std::strncmp(s+p, "<double>", 8) == 0)
                        ? get_parameter_tag_runtime(s, find_closing_tag_runtime(s, p)) * 6 + 3 :
                    (std::strncmp(s+p, "<str>", 5) == 0 ||
                    std::strncmp(s+p, "<string>", 8) == 0)
                        ? get_parameter_tag_runtime(s, find_closing_tag_runtime(s, p)) * 6 + 4 :
                    std::strncmp(s+p, "<path>", 6) == 0
                        ? get_parameter_tag_runtime(s, find_closing_tag_runtime(s, p)) * 6 + 5 :
                    throw std::runtime_error("invalid parameter type")
                    ) :
                get_parameter_tag_runtime(s, p+1);
        }

        constexpr uint64_t get_parameter_tag(const_str s, unsigned p = 0)
        {
            return
                p == s.size()
                    ? 0 :
                s[p] == '<' ? (
                    is_int(s, p)
                        ? get_parameter_tag(s, find_closing_tag(s, p)) * 6 + 1 :
                    is_uint(s, p)
                        ? get_parameter_tag(s, find_closing_tag(s, p)) * 6 + 2 :
                    is_float(s, p)
                        ? get_parameter_tag(s, find_closing_tag(s, p)) * 6 + 3 :
                    is_str(s, p)
                        ? get_parameter_tag(s, find_closing_tag(s, p)) * 6 + 4 :
                    is_path(s, p)
                        ? get_parameter_tag(s, find_closing_tag(s, p)) * 6 + 5 :
                    throw std::runtime_error("invalid parameter type")
                    ) :
                get_parameter_tag(s, p+1);
        }


        template <typename ... T>
        struct S
        {
            template <typename U>
            using push = S<U, T...>;
            template <typename U>
            using push_back = S<T..., U>;
            template <template<typename ... Args> class U>
            using rebind = U<T...>;
        };
template <typename F, typename Set>
        struct CallHelper;
        template <typename F, typename ...Args>
        struct CallHelper<F, S<Args...>>
        {
            template <typename F1, typename ...Args1, typename =
                decltype(std::declval<F1>()(std::declval<Args1>()...))
                >
            static char __test(int);

            template <typename ...>
            static int __test(...);

            static constexpr bool value = sizeof(__test<F, Args...>(0)) == sizeof(char);
        };


        template <int N>
        struct single_tag_to_type
        {
        };

        template <>
        struct single_tag_to_type<1>
        {
            using type = int64_t;
        };

        template <>
        struct single_tag_to_type<2>
        {
            using type = uint64_t;
        };

        template <>
        struct single_tag_to_type<3>
        {
            using type = double;
        };

        template <>
        struct single_tag_to_type<4>
        {
            using type = std::string;
        };

        template <>
        struct single_tag_to_type<5>
        {
            using type = std::string;
        };


        template <uint64_t Tag>
        struct arguments
        {
            using subarguments = typename arguments<Tag/6>::type;
            using type =
                typename subarguments::template push<typename single_tag_to_type<Tag%6>::type>;
        };

        template <>
        struct arguments<0>
        {
            using type = S<>;
        };

        template <typename ... T>
        struct last_element_type
        {
            using type = typename std::tuple_element<sizeof...(T)-1, std::tuple<T...>>::type;
        };


        template <>
        struct last_element_type<>
        {
        };



        template<class T> using Invoke = typename T::type;

        template<unsigned...> struct seq{ using type = seq; };

        template<class S1, class S2> struct concat;

        template<unsigned... I1, unsigned... I2>
        struct concat<seq<I1...>, seq<I2...>>
          : seq<I1..., (sizeof...(I1)+I2)...>{};

        template<class S1, class S2>
        using Concat = Invoke<concat<S1, S2>>;

        template<unsigned N> struct gen_seq;
        template<unsigned N> using GenSeq = Invoke<gen_seq<N>>;

        template<unsigned N>
        struct gen_seq : Concat<GenSeq<N/2>, GenSeq<N - N/2>>{};

        template<> struct gen_seq<0> : seq<>{};
        template<> struct gen_seq<1> : seq<0>{};

        template <typename Seq, typename Tuple>
        struct pop_back_helper;

        template <unsigned ... N, typename Tuple>
        struct pop_back_helper<seq<N...>, Tuple>
        {
            template <template <typename ... Args> class U>
            using rebind = U<typename std::tuple_element<N, Tuple>::type...>;
        };

        template <typename ... T>
        struct pop_back
        {
            template <template <typename ... Args> class U>
            using rebind = typename pop_back_helper<typename gen_seq<sizeof...(T)-1>::type, std::tuple<T...>>::template rebind<U>;
        };

        template <>
        struct pop_back<>
        {
            template <template <typename ... Args> class U>
            using rebind = U<>;
        };


        template < typename Tp, typename... List >
        struct contains : std::true_type {};

        template < typename Tp, typename Head, typename... Rest >
        struct contains<Tp, Head, Rest...>
        : std::conditional< std::is_same<Tp, Head>::value,
            std::true_type,
            contains<Tp, Rest...>
        >::type {};

        template < typename Tp >
        struct contains<Tp> : std::false_type {};

        template <typename T>
        struct empty_context
        {
        };

        template <typename T>
        struct promote
        {
            using type = T;
        };

        template<> struct promote<char> { using type = int64_t; };
        template<> struct promote<short> { using type = int64_t; };
        template<> struct promote<int> { using type = int64_t; };
        template<> struct promote<long> { using type = int64_t; };
        template<> struct promote<long long> { using type = int64_t; };
        template<> struct promote<unsigned char> { using type = uint64_t; };
        template<> struct promote<unsigned short> { using type = uint64_t; };
        template<> struct promote<unsigned int> { using type = uint64_t; };
        template<> struct promote<unsigned long> { using type = uint64_t; };
        template<> struct promote<unsigned long long> { using type = uint64_t; };
        template<> struct promote<float> { using type = double; };


        template <typename T>
        using promote_t = typename promote<T>::type;

    }

    namespace detail
    {

        template <class T, std::size_t N, class... Args>
        struct get_index_of_element_from_tuple_by_type_impl
        {
            static constexpr auto value = N;
        };

        template <class T, std::size_t N, class... Args>
        struct get_index_of_element_from_tuple_by_type_impl<T, N, T, Args...>
        {
            static constexpr auto value = N;
        };

        template <class T, std::size_t N, class U, class... Args>
        struct get_index_of_element_from_tuple_by_type_impl<T, N, U, Args...>
        {
            static constexpr auto value = get_index_of_element_from_tuple_by_type_impl<T, N + 1, Args...>::value;
        };

    }

    namespace utility
    {
        template <class T, class... Args>
        T& get_element_by_type(std::tuple<Args...>& t)
        {
            return std::get<detail::get_index_of_element_from_tuple_by_type_impl<T, 0, Args...>::value>(t);
        }

        template<typename T>
        struct function_traits;


        template<typename T>
        struct function_traits : public function_traits<decltype(&T::operator())>
        {
            using parent_t = function_traits<decltype(&T::operator())>;
            static const size_t arity = parent_t::arity;
            using result_type = typename parent_t::result_type;
            template <size_t i>
            using arg = typename parent_t::template arg<i>;

        };


        template<typename ClassType, typename R, typename ...Args>
        struct function_traits<R(ClassType::*)(Args...) const>
        {
            static const size_t arity = sizeof...(Args);

            typedef R result_type;

            template <size_t i>
            using arg = typename std::tuple_element<i, std::tuple<Args...>>::type;
        };

        template<typename ClassType, typename R, typename ...Args>
        struct function_traits<R(ClassType::*)(Args...)>
        {
            static const size_t arity = sizeof...(Args);

            typedef R result_type;

            template <size_t i>
            using arg = typename std::tuple_element<i, std::tuple<Args...>>::type;
        };

        template<typename R, typename ...Args>
        struct function_traits<std::function<R(Args...)>>
        {
            static const size_t arity = sizeof...(Args);

            typedef R result_type;

            template <size_t i>
            using arg = typename std::tuple_element<i, std::tuple<Args...>>::type;
        };

        inline static std::string base64encode(const char* data, size_t size, const char* key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        {
            std::string ret;
            ret.resize((size+2) / 3 * 4);
            auto it = ret.begin();
            while(size >= 3)
            {
                *it++ = key[(((unsigned char)*data)&0xFC)>>2];
                unsigned char h = (((unsigned char)*data++) & 0x03) << 4;
                *it++ = key[h|((((unsigned char)*data)&0xF0)>>4)];
                h = (((unsigned char)*data++) & 0x0F) << 2;
                *it++ = key[h|((((unsigned char)*data)&0xC0)>>6)];
                *it++ = key[((unsigned char)*data++)&0x3F];

                size -= 3;
            }
            if (size == 1)
            {
                *it++ = key[(((unsigned char)*data)&0xFC)>>2];
                unsigned char h = (((unsigned char)*data++) & 0x03) << 4;
                *it++ = key[h];
                *it++ = '=';
                *it++ = '=';
            }
            else if (size == 2)
            {
                *it++ = key[(((unsigned char)*data)&0xFC)>>2];
                unsigned char h = (((unsigned char)*data++) & 0x03) << 4;
                *it++ = key[h|((((unsigned char)*data)&0xF0)>>4)];
                h = (((unsigned char)*data++) & 0x0F) << 2;
                *it++ = key[h];
                *it++ = '=';
            }
            return ret;
        }

        inline static std::string base64encode_urlsafe(const char* data, size_t size)
        {
            return base64encode(data, size, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
        }


    }
}


       







namespace crow
{
    enum class HTTPMethod
    {

        DELETE = 0,
        GET,
        HEAD,
        POST,
        PUT,
        CONNECT,
        OPTIONS,
        TRACE,
        PATCH,
        PURGE,


        Delete = 0,
        Get,
        Head,
        Post,
        Put,
        Connect,
        Options,
        Trace,
        Patch,
        Purge,


        InternalMethodCount,

    };

    inline std::string method_name(HTTPMethod method)
    {
        switch(method)
        {
            case HTTPMethod::Delete:
                return "DELETE";
            case HTTPMethod::Get:
                return "GET";
            case HTTPMethod::Head:
                return "HEAD";
            case HTTPMethod::Post:
                return "POST";
            case HTTPMethod::Put:
                return "PUT";
            case HTTPMethod::Connect:
                return "CONNECT";
            case HTTPMethod::Options:
                return "OPTIONS";
            case HTTPMethod::Trace:
                return "TRACE";
            case HTTPMethod::Patch:
                return "PATCH";
            case HTTPMethod::Purge:
                return "PURGE";
            default:
                return "invalid";
        }
        return "invalid";
    }

    enum class ParamType
    {
        INT,
        UINT,
        DOUBLE,
        STRING,
        PATH,

        MAX
    };

    struct routing_params
    {
        std::vector<int64_t> int_params;
        std::vector<uint64_t> uint_params;
        std::vector<double> double_params;
        std::vector<std::string> string_params;

        void debug_print() const
        {
            std::cerr << "routing_params" << std::endl;
            for(auto i:int_params)
                std::cerr<<i <<", " ;
            std::cerr<<std::endl;
            for(auto i:uint_params)
                std::cerr<<i <<", " ;
            std::cerr<<std::endl;
            for(auto i:double_params)
                std::cerr<<i <<", " ;
            std::cerr<<std::endl;
            for(auto& i:string_params)
                std::cerr<<i <<", " ;
            std::cerr<<std::endl;
        }

        template <typename T>
        T get(unsigned) const;

    };

    template<>
    inline int64_t routing_params::get<int64_t>(unsigned index) const
    {
        return int_params[index];
    }

    template<>
    inline uint64_t routing_params::get<uint64_t>(unsigned index) const
    {
        return uint_params[index];
    }

    template<>
    inline double routing_params::get<double>(unsigned index) const
    {
        return double_params[index];
    }

    template<>
    inline std::string routing_params::get<std::string>(unsigned index) const
    {
        return string_params[index];
    }
}


constexpr crow::HTTPMethod operator "" _method(const char* str, size_t )
{
    return
        crow::black_magic::is_equ_p(str, "GET", 3) ? crow::HTTPMethod::Get :
        crow::black_magic::is_equ_p(str, "DELETE", 6) ? crow::HTTPMethod::Delete :
        crow::black_magic::is_equ_p(str, "HEAD", 4) ? crow::HTTPMethod::Head :
        crow::black_magic::is_equ_p(str, "POST", 4) ? crow::HTTPMethod::Post :
        crow::black_magic::is_equ_p(str, "PUT", 3) ? crow::HTTPMethod::Put :
        crow::black_magic::is_equ_p(str, "OPTIONS", 7) ? crow::HTTPMethod::Options :
        crow::black_magic::is_equ_p(str, "CONNECT", 7) ? crow::HTTPMethod::Connect :
        crow::black_magic::is_equ_p(str, "TRACE", 5) ? crow::HTTPMethod::Trace :
        crow::black_magic::is_equ_p(str, "PATCH", 5) ? crow::HTTPMethod::Patch :
        crow::black_magic::is_equ_p(str, "PURGE", 5) ? crow::HTTPMethod::Purge :
        throw std::runtime_error("invalid http method");
}


       







namespace crow
{
    template <typename T>
    inline const std::string& get_header_value(const T& headers, const std::string& key)
    {
        if (headers.count(key))
        {
            return headers.find(key)->second;
        }
        static std::string empty;
        return empty;
    }

 struct DetachHelper;

    struct request
    {
        HTTPMethod method;
        std::string raw_url;
        std::string url;
        query_string url_params;
        ci_map headers;
        std::string body;

        void* middleware_context{};
        boost::asio::io_service* io_service{};

        request()
            : method(HTTPMethod::Get)
        {
        }

        request(HTTPMethod method, std::string raw_url, std::string url, query_string url_params, ci_map headers, std::string body)
            : method(method), raw_url(std::move(raw_url)), url(std::move(url)), url_params(std::move(url_params)), headers(std::move(headers)), body(std::move(body))
        {
        }

        void add_header(std::string key, std::string value)
        {
            headers.emplace(std::move(key), std::move(value));
        }

        const std::string& get_header_value(const std::string& key) const
        {
            return crow::get_header_value(headers, key);
        }

        template<typename CompletionHandler>
        void post(CompletionHandler handler)
        {
            io_service->post(handler);
        }

        template<typename CompletionHandler>
        void dispatch(CompletionHandler handler)
        {
            io_service->dispatch(handler);
        }

    };
}


       







namespace crow
{
    namespace websocket
    {
        enum class WebSocketReadState
        {
            MiniHeader,
            Len16,
            Len64,
            Mask,
            Payload,
        };

  struct connection
  {
            virtual void send_binary(const std::string& msg) = 0;
            virtual void send_text(const std::string& msg) = 0;
            virtual void close(const std::string& msg = "quit") = 0;
            virtual ~connection(){}

            void userdata(void* u) { userdata_ = u; }
            void* userdata() { return userdata_; }

        private:
            void* userdata_;
  };

  template <typename Adaptor>
        class Connection : public connection
        {
   public:
    Connection(const crow::request& req, Adaptor&& adaptor,
      std::function<void(crow::websocket::connection&)> open_handler,
      std::function<void(crow::websocket::connection&, const std::string&, bool)> message_handler,
      std::function<void(crow::websocket::connection&, const std::string&)> close_handler,
      std::function<void(crow::websocket::connection&)> error_handler,
      std::function<bool(const crow::request&)> accept_handler)
     : adaptor_(std::move(adaptor)), open_handler_(std::move(open_handler)), message_handler_(std::move(message_handler)), close_handler_(std::move(close_handler)), error_handler_(std::move(error_handler))
     , accept_handler_(std::move(accept_handler))
    {
     if (!boost::iequals(req.get_header_value("upgrade"), "websocket"))
     {
      adaptor.close();
      delete this;
      return;
     }

     if (accept_handler_)
     {
      if (!accept_handler_(req))
      {
       adaptor.close();
       delete this;
       return;
      }
     }



                    std::string magic = req.get_header_value("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                    sha1::SHA1 s;
                    s.processBytes(magic.data(), magic.size());
                    uint8_t digest[20];
                    s.getDigestBytes(digest);
                    start(crow::utility::base64encode((char*)digest, 20));
    }

                template<typename CompletionHandler>
                void dispatch(CompletionHandler handler)
                {
                    adaptor_.get_io_service().dispatch(handler);
                }

                template<typename CompletionHandler>
                void post(CompletionHandler handler)
                {
                    adaptor_.get_io_service().post(handler);
                }

                void send_pong(const std::string& msg)
                {
                    dispatch([this, msg]{
                        char buf[3] = "\x8A\x00";
                        buf[1] += msg.size();
                        write_buffers_.emplace_back(buf, buf+2);
                        write_buffers_.emplace_back(msg);
                        do_write();
                    });
                }

                void send_binary(const std::string& msg) override
                {
                    dispatch([this, msg]{
                        auto header = build_header(2, msg.size());
                        write_buffers_.emplace_back(std::move(header));
                        write_buffers_.emplace_back(msg);
                        do_write();
                    });
                }

                void send_text(const std::string& msg) override
                {
                    dispatch([this, msg]{
                        auto header = build_header(1, msg.size());
                        write_buffers_.emplace_back(std::move(header));
                        write_buffers_.emplace_back(msg);
                        do_write();
                    });
                }

                void close(const std::string& msg) override
                {
                    dispatch([this, msg]{
                        has_sent_close_ = true;
                        if (has_recv_close_ && !is_close_handler_called_)
                        {
                            is_close_handler_called_ = true;
                            if (close_handler_)
                                close_handler_(*this, msg);
                        }
                        auto header = build_header(0x8, msg.size());
                        write_buffers_.emplace_back(std::move(header));
                        write_buffers_.emplace_back(msg);
                        do_write();
                    });
                }

            protected:

                std::string build_header(int opcode, size_t size)
                {
                    char buf[2+8] = "\x80\x00";
                    buf[0] += opcode;
                    if (size < 126)
                    {
                        buf[1] += size;
                        return {buf, buf+2};
                    }
                    else if (size < 0x10000)
                    {
                        buf[1] += 126;
                        *(uint16_t*)(buf+2) = htons((uint16_t)size);
                        return {buf, buf+4};
                    }
                    else
                    {
                        buf[1] += 127;
                        *reinterpret_cast<uint64_t*>(buf+2) = ((1==htonl(1)) ? static_cast<uint64_t>(size) : (static_cast<uint64_t>(htonl((size) & 0xFFFFFFFF)) << 32) | htonl(static_cast<uint64_t>(size) >> 32));
                        return {buf, buf+10};
                    }
                }

                void start(std::string&& hello)
                {
                    static std::string header = "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: ";
                    static std::string crlf = "\r\n";
                    write_buffers_.emplace_back(header);
                    write_buffers_.emplace_back(std::move(hello));
                    write_buffers_.emplace_back(crlf);
                    write_buffers_.emplace_back(crlf);
                    do_write();
                    if (open_handler_)
                        open_handler_(*this);
                    do_read();
                }

                void do_read()
                {
                    is_reading = true;
                    switch(state_)
                    {
                        case WebSocketReadState::MiniHeader:
                            {

                                adaptor_.socket().async_read_some(boost::asio::buffer(&mini_header_, 2),
                                    [this](const boost::system::error_code& ec, std::size_t



                                        )

                                    {
                                        is_reading = false;
                                        mini_header_ = ntohs(mini_header_);

                                        if (!ec && ((mini_header_ & 0x80) == 0x80))
                                        {
                                            if ((mini_header_ & 0x7f) == 127)
                                            {
                                                state_ = WebSocketReadState::Len64;
                                            }
                                            else if ((mini_header_ & 0x7f) == 126)
                                            {
                                                state_ = WebSocketReadState::Len16;
                                            }
                                            else
                                            {
                                                remaining_length_ = mini_header_ & 0x7f;
                                                state_ = WebSocketReadState::Mask;
                                            }
                                            do_read();
                                        }
                                        else
                                        {
                                            close_connection_ = true;
                                            adaptor_.close();
                                            if (error_handler_)
                                                error_handler_(*this);
                                            check_destroy();
                                        }
                                    });
                            }
                            break;
                        case WebSocketReadState::Len16:
                            {
                                remaining_length_ = 0;
                                remaining_length16_ = 0;
                                boost::asio::async_read(adaptor_.socket(), boost::asio::buffer(&remaining_length16_, 2),
                                    [this](const boost::system::error_code& ec, std::size_t



                                        )
                                    {
                                        is_reading = false;
                                        remaining_length16_ = ntohs(remaining_length16_);
                                        remaining_length_ = remaining_length16_;







                                        if (!ec)
                                        {
                                            state_ = WebSocketReadState::Mask;
                                            do_read();
                                        }
                                        else
                                        {
                                            close_connection_ = true;
                                            adaptor_.close();
                                            if (error_handler_)
                                                error_handler_(*this);
                                            check_destroy();
                                        }
                                    });
                            }
                            break;
                        case WebSocketReadState::Len64:
                            {
                                boost::asio::async_read(adaptor_.socket(), boost::asio::buffer(&remaining_length_, 8),
                                    [this](const boost::system::error_code& ec, std::size_t



                                        )
                                    {
                                        is_reading = false;
                                        remaining_length_ = ((1==ntohl(1)) ? (remaining_length_) : ((uint64_t)ntohl((remaining_length_) & 0xFFFFFFFF) << 32) | ntohl((remaining_length_) >> 32));







                                        if (!ec)
                                        {
                                            state_ = WebSocketReadState::Mask;
                                            do_read();
                                        }
                                        else
                                        {
                                            close_connection_ = true;
                                            adaptor_.close();
                                            if (error_handler_)
                                                error_handler_(*this);
                                            check_destroy();
                                        }
                                    });
                            }
                            break;
                        case WebSocketReadState::Mask:
                                boost::asio::async_read(adaptor_.socket(), boost::asio::buffer((char*)&mask_, 4),
                                    [this](const boost::system::error_code& ec, std::size_t



                                    )
                                    {
                                        is_reading = false;







                                        if (!ec)
                                        {
                                            state_ = WebSocketReadState::Payload;
                                            do_read();
                                        }
                                        else
                                        {
                                            close_connection_ = true;
                                            if (error_handler_)
                                                error_handler_(*this);
                                            adaptor_.close();
                                        }
                                    });
                            break;
                        case WebSocketReadState::Payload:
                            {
                                size_t to_read = buffer_.size();
                                if (remaining_length_ < to_read)
                                    to_read = remaining_length_;
                                adaptor_.socket().async_read_some( boost::asio::buffer(buffer_, to_read),
                                    [this](const boost::system::error_code& ec, std::size_t bytes_transferred)
                                    {
                                        is_reading = false;

                                        if (!ec)
                                        {
                                            fragment_.insert(fragment_.end(), buffer_.begin(), buffer_.begin() + bytes_transferred);
                                            remaining_length_ -= bytes_transferred;
                                            if (remaining_length_ == 0)
                                            {
                                                handle_fragment();
                                                state_ = WebSocketReadState::MiniHeader;
                                                do_read();
                                            }
                                        }
                                        else
                                        {
                                            close_connection_ = true;
                                            if (error_handler_)
                                                error_handler_(*this);
                                            adaptor_.close();
                                        }
                                    });
                            }
                            break;
                    }
                }

                bool is_FIN()
                {
                    return mini_header_ & 0x8000;
                }

                int opcode()
                {
                    return (mini_header_ & 0x0f00) >> 8;
                }

                void handle_fragment()
                {
                    for(decltype(fragment_.length()) i = 0; i < fragment_.length(); i ++)
                    {
                        fragment_[i] ^= ((char*)&mask_)[i%4];
                    }
                    switch(opcode())
                    {
                        case 0:
                            {
                                message_ += fragment_;
                                if (is_FIN())
                                {
                                    if (message_handler_)
                                        message_handler_(*this, message_, is_binary_);
                                    message_.clear();
                                }
                            }
                        case 1:
                            {
                                is_binary_ = false;
                                message_ += fragment_;
                                if (is_FIN())
                                {
                                    if (message_handler_)
                                        message_handler_(*this, message_, is_binary_);
                                    message_.clear();
                                }
                            }
                            break;
                        case 2:
                            {
                                is_binary_ = true;
                                message_ += fragment_;
                                if (is_FIN())
                                {
                                    if (message_handler_)
                                        message_handler_(*this, message_, is_binary_);
                                    message_.clear();
                                }
                            }
                            break;
                        case 0x8:
                            {
                                has_recv_close_ = true;
                                if (!has_sent_close_)
                                {
                                    close(fragment_);
                                }
                                else
                                {
                                    adaptor_.close();
                                    close_connection_ = true;
                                    if (!is_close_handler_called_)
                                    {
                                        if (close_handler_)
                                            close_handler_(*this, fragment_);
                                        is_close_handler_called_ = true;
                                    }
                                    check_destroy();
                                }
                            }
                            break;
                        case 0x9:
                            {
                                send_pong(fragment_);
                            }
                            break;
                        case 0xA:
                            {
                                pong_received_ = true;
                            }
                            break;
                    }

                    fragment_.clear();
                }

                void do_write()
                {
                    if (sending_buffers_.empty())
                    {
                        sending_buffers_.swap(write_buffers_);
                        std::vector<boost::asio::const_buffer> buffers;
                        buffers.reserve(sending_buffers_.size());
                        for(auto& s:sending_buffers_)
                        {
                            buffers.emplace_back(boost::asio::buffer(s));
                        }
                        boost::asio::async_write(adaptor_.socket(), buffers,
                            [&](const boost::system::error_code& ec, std::size_t )
                            {
                                sending_buffers_.clear();
                                if (!ec && !close_connection_)
                                {
                                    if (!write_buffers_.empty())
                                        do_write();
                                    if (has_sent_close_)
                                        close_connection_ = true;
                                }
                                else
                                {
                                    close_connection_ = true;
                                    check_destroy();
                                }
                            });
                    }
                }

                void check_destroy()
                {

                    if (!is_close_handler_called_)
                        if (close_handler_)
                            close_handler_(*this, "uncleanly");
                    if (sending_buffers_.empty() && !is_reading)
                        delete this;
                }
   private:
    Adaptor adaptor_;

                std::vector<std::string> sending_buffers_;
                std::vector<std::string> write_buffers_;

                boost::array<char, 4096> buffer_;
                bool is_binary_;
                std::string message_;
                std::string fragment_;
                WebSocketReadState state_{WebSocketReadState::MiniHeader};
                uint16_t remaining_length16_{0};
                uint64_t remaining_length_{0};
                bool close_connection_{false};
                bool is_reading{false};
                uint32_t mask_;
                uint16_t mini_header_;
                bool has_sent_close_{false};
                bool has_recv_close_{false};
                bool error_occured_{false};
                bool pong_received_{false};
                bool is_close_handler_called_{false};

    std::function<void(crow::websocket::connection&)> open_handler_;
    std::function<void(crow::websocket::connection&, const std::string&, bool)> message_handler_;
    std::function<void(crow::websocket::connection&, const std::string&)> close_handler_;
    std::function<void(crow::websocket::connection&)> error_handler_;
    std::function<bool(const crow::request&)> accept_handler_;
        };
    }
}


       










namespace crow
{
    template <typename Handler>
    struct HTTPParser : public http_parser
    {
        static int on_message_begin(http_parser* self_)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);
            self->clear();
            return 0;
        }
        static int on_url(http_parser* self_, const char* at, size_t length)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);
            self->raw_url.insert(self->raw_url.end(), at, at+length);
            return 0;
        }
        static int on_header_field(http_parser* self_, const char* at, size_t length)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);
            switch (self->header_building_state)
            {
                case 0:
                    if (!self->header_value.empty())
                    {
                        self->headers.emplace(std::move(self->header_field), std::move(self->header_value));
                    }
                    self->header_field.assign(at, at+length);
                    self->header_building_state = 1;
                    break;
                case 1:
                    self->header_field.insert(self->header_field.end(), at, at+length);
                    break;
            }
            return 0;
        }
        static int on_header_value(http_parser* self_, const char* at, size_t length)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);
            switch (self->header_building_state)
            {
                case 0:
                    self->header_value.insert(self->header_value.end(), at, at+length);
                    break;
                case 1:
                    self->header_building_state = 0;
                    self->header_value.assign(at, at+length);
                    break;
            }
            return 0;
        }
        static int on_headers_complete(http_parser* self_)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);
            if (!self->header_field.empty())
            {
                self->headers.emplace(std::move(self->header_field), std::move(self->header_value));
            }
            self->process_header();
            return 0;
        }
        static int on_body(http_parser* self_, const char* at, size_t length)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);
            self->body.insert(self->body.end(), at, at+length);
            return 0;
        }
        static int on_message_complete(http_parser* self_)
        {
            HTTPParser* self = static_cast<HTTPParser*>(self_);


            self->url = self->raw_url.substr(0, self->raw_url.find("?"));
            self->url_params = query_string(self->raw_url);

            self->process_message();
            return 0;
        }
        HTTPParser(Handler* handler) :
            handler_(handler)
        {
            http_parser_init(this, HTTP_REQUEST);
        }


        bool feed(const char* buffer, int length)
        {
            const static http_parser_settings settings_{
                on_message_begin,
                on_url,
                nullptr,
                on_header_field,
                on_header_value,
                on_headers_complete,
                on_body,
                on_message_complete,
            };

            int nparsed = http_parser_execute(this, &settings_, buffer, length);
            return nparsed == length;
        }

        bool done()
        {
            return feed(nullptr, 0);
        }

        void clear()
        {
            url.clear();
            raw_url.clear();
            header_building_state = 0;
            header_field.clear();
            header_value.clear();
            headers.clear();
            url_params.clear();
            body.clear();
        }

        void process_header()
        {
            handler_->handle_header();
        }

        void process_message()
        {
            handler_->handle();
        }

        request to_request() const
        {
            return request{(HTTPMethod)method, std::move(raw_url), std::move(url), std::move(url_params), std::move(headers), std::move(body)};
        }

  bool is_upgrade() const
  {
   return upgrade;
  }

        bool check_version(int major, int minor) const
        {
            return http_major == major && http_minor == minor;
        }

        std::string raw_url;
        std::string url;

        int header_building_state = 0;
        std::string header_field;
        std::string header_value;
        ci_map headers;
        query_string url_params;
        std::string body;

        Handler* handler_;
    };
}


       







namespace crow
{
    template <typename Adaptor, typename Handler, typename ... Middlewares>
    class Connection;
    struct response
    {
        template <typename Adaptor, typename Handler, typename ... Middlewares>
        friend class crow::Connection;

        int code{200};
        std::string body;
        json::wvalue json_value;


        ci_map headers;

        void set_header(std::string key, std::string value)
        {
            headers.erase(key);
            headers.emplace(std::move(key), std::move(value));
        }
        void add_header(std::string key, std::string value)
        {
            headers.emplace(std::move(key), std::move(value));
        }

        const std::string& get_header_value(const std::string& key)
        {
            return crow::get_header_value(headers, key);
        }


        response() {}
        explicit response(int code) : code(code) {}
        response(std::string body) : body(std::move(body)) {}
        response(json::wvalue&& json_value) : json_value(std::move(json_value))
        {
            json_mode();
        }
        response(int code, std::string body) : code(code), body(std::move(body)) {}
        response(const json::wvalue& json_value) : body(json::dump(json_value))
        {
            json_mode();
        }
        response(int code, const json::wvalue& json_value) : code(code), body(json::dump(json_value))
        {
            json_mode();
        }

        response(response&& r)
        {
            *this = std::move(r);
        }

        response& operator = (const response& r) = delete;

        response& operator = (response&& r) noexcept
        {
            body = std::move(r.body);
            json_value = std::move(r.json_value);
            code = r.code;
            headers = std::move(r.headers);
            completed_ = r.completed_;
            return *this;
        }

        bool is_completed() const noexcept
        {
            return completed_;
        }

        void clear()
        {
            body.clear();
            json_value.clear();
            code = 200;
            headers.clear();
            completed_ = false;
        }

        void redirect(const std::string& location)
        {
            code = 301;
            set_header("Location", location);
        }

        void write(const std::string& body_part)
        {
            body += body_part;
        }

        void end()
        {
            if (!completed_)
            {
                completed_ = true;

                if (complete_request_handler_)
                {
                    complete_request_handler_();
                }
            }
        }

        void end(const std::string& body_part)
        {
            body += body_part;
            end();
        }

        bool is_alive()
        {
            return is_alive_helper_ && is_alive_helper_();
        }

        private:
            bool completed_{};
            std::function<void()> complete_request_handler_;
            std::function<bool()> is_alive_helper_;


            void json_mode()
            {
                set_header("Content-Type", "application/json");
            }
    };
}


       




namespace crow
{

    struct CookieParser
    {
        struct context
        {
            std::unordered_map<std::string, std::string> jar;
            std::unordered_map<std::string, std::string> cookies_to_add;

            std::string get_cookie(const std::string& key) const
            {
                auto cookie = jar.find(key);
                if (cookie != jar.end())
                    return cookie->second;
                return {};
            }

            void set_cookie(const std::string& key, const std::string& value)
            {
                cookies_to_add.emplace(key, value);
            }
        };

        void before_handle(request& req, response& res, context& ctx)
        {
            int count = req.headers.count("Cookie");
            if (!count)
                return;
            if (count > 1)
            {
                res.code = 400;
                res.end();
                return;
            }
            std::string cookies = req.get_header_value("Cookie");
            size_t pos = 0;
            while(pos < cookies.size())
            {
                size_t pos_equal = cookies.find('=', pos);
                if (pos_equal == cookies.npos)
                    break;
                std::string name = cookies.substr(pos, pos_equal-pos);
                boost::trim(name);
                pos = pos_equal+1;
                while(pos < cookies.size() && cookies[pos] == ' ') pos++;
                if (pos == cookies.size())
                    break;

                size_t pos_semicolon = cookies.find(';', pos);
                std::string value = cookies.substr(pos, pos_semicolon-pos);

                boost::trim(value);
                if (value[0] == '"' && value[value.size()-1] == '"')
                {
                    value = value.substr(1, value.size()-2);
                }

                ctx.jar.emplace(std::move(name), std::move(value));

                pos = pos_semicolon;
                if (pos == cookies.npos)
                    break;
                pos++;
                while(pos < cookies.size() && cookies[pos] == ' ') pos++;
            }
        }

        void after_handle(request& , response& res, context& ctx)
        {
            for(auto& cookie:ctx.cookies_to_add)
            {
                if (cookie.second.empty())
                    res.add_header("Set-Cookie", cookie.first + "=\"\"");
                else
                    res.add_header("Set-Cookie", cookie.first + "=" + cookie.second);
            }
        }
    };

}


       









namespace crow
{
    class BaseRule
    {
    public:
        BaseRule(std::string rule)
            : rule_(std::move(rule))
        {
        }

        virtual ~BaseRule()
        {
        }

        virtual void validate() = 0;
        std::unique_ptr<BaseRule> upgrade()
        {
            if (rule_to_upgrade_)
                return std::move(rule_to_upgrade_);
            return {};
        }

        virtual void handle(const request&, response&, const routing_params&) = 0;
        virtual void handle_upgrade(const request&, response& res, SocketAdaptor&&)
        {
            res = response(404);
            res.end();
        }

        uint32_t get_methods()
        {
            return methods_;
        }

        template <typename F>
        void foreach_method(F f)
        {
            for(uint32_t method = 0, method_bit = 1; method < (uint32_t)HTTPMethod::InternalMethodCount; method++, method_bit<<=1)
            {
                if (methods_ & method_bit)
                    f(method);
            }
        }

        const std::string& rule() { return rule_; }

    protected:
        uint32_t methods_{1<<(int)HTTPMethod::Get};

        std::string rule_;
        std::string name_;

        std::unique_ptr<BaseRule> rule_to_upgrade_;

        friend class Router;
        template <typename T>
        friend struct RuleParameterTraits;
    };


    namespace detail
    {
        namespace routing_handler_call_helper
        {
            template <typename T, int Pos>
            struct call_pair
            {
                using type = T;
                static const int pos = Pos;
            };

            template <typename H1>
            struct call_params
            {
                H1& handler;
                const routing_params& params;
                const request& req;
                response& res;
            };

            template <typename F, int NInt, int NUint, int NDouble, int NString, typename S1, typename S2>
            struct call
            {
            };

            template <typename F, int NInt, int NUint, int NDouble, int NString, typename ... Args1, typename ... Args2>
            struct call<F, NInt, NUint, NDouble, NString, black_magic::S<int64_t, Args1...>, black_magic::S<Args2...>>
            {
                void operator()(F cparams)
                {
                    using pushed = typename black_magic::S<Args2...>::template push_back<call_pair<int64_t, NInt>>;
                    call<F, NInt+1, NUint, NDouble, NString,
                        black_magic::S<Args1...>, pushed>()(cparams);
                }
            };

            template <typename F, int NInt, int NUint, int NDouble, int NString, typename ... Args1, typename ... Args2>
            struct call<F, NInt, NUint, NDouble, NString, black_magic::S<uint64_t, Args1...>, black_magic::S<Args2...>>
            {
                void operator()(F cparams)
                {
                    using pushed = typename black_magic::S<Args2...>::template push_back<call_pair<uint64_t, NUint>>;
                    call<F, NInt, NUint+1, NDouble, NString,
                        black_magic::S<Args1...>, pushed>()(cparams);
                }
            };

            template <typename F, int NInt, int NUint, int NDouble, int NString, typename ... Args1, typename ... Args2>
            struct call<F, NInt, NUint, NDouble, NString, black_magic::S<double, Args1...>, black_magic::S<Args2...>>
            {
                void operator()(F cparams)
                {
                    using pushed = typename black_magic::S<Args2...>::template push_back<call_pair<double, NDouble>>;
                    call<F, NInt, NUint, NDouble+1, NString,
                        black_magic::S<Args1...>, pushed>()(cparams);
                }
            };

            template <typename F, int NInt, int NUint, int NDouble, int NString, typename ... Args1, typename ... Args2>
            struct call<F, NInt, NUint, NDouble, NString, black_magic::S<std::string, Args1...>, black_magic::S<Args2...>>
            {
                void operator()(F cparams)
                {
                    using pushed = typename black_magic::S<Args2...>::template push_back<call_pair<std::string, NString>>;
                    call<F, NInt, NUint, NDouble, NString+1,
                        black_magic::S<Args1...>, pushed>()(cparams);
                }
            };

            template <typename F, int NInt, int NUint, int NDouble, int NString, typename ... Args1>
            struct call<F, NInt, NUint, NDouble, NString, black_magic::S<>, black_magic::S<Args1...>>
            {
                void operator()(F cparams)
                {
                    cparams.handler(
                        cparams.req,
                        cparams.res,
                        cparams.params.template get<typename Args1::type>(Args1::pos)...
                    );
                }
            };

            template <typename Func, typename ... ArgsWrapped>
            struct Wrapped
            {
                template <typename ... Args>
                void set_(Func f, typename std::enable_if<
                    !std::is_same<typename std::tuple_element<0, std::tuple<Args..., void>>::type, const request&>::value
                , int>::type = 0)
                {
                    handler_ = (



                        [f]

                        (const request&, response& res, Args... args){
                            res = response(f(args...));
                            res.end();
                        });
                }

                template <typename Req, typename ... Args>
                struct req_handler_wrapper
                {
                    req_handler_wrapper(Func f)
                        : f(std::move(f))
                    {
                    }

                    void operator()(const request& req, response& res, Args... args)
                    {
                        res = response(f(req, args...));
                        res.end();
                    }

                    Func f;
                };

                template <typename ... Args>
                void set_(Func f, typename std::enable_if<
                        std::is_same<typename std::tuple_element<0, std::tuple<Args..., void>>::type, const request&>::value &&
                        !std::is_same<typename std::tuple_element<1, std::tuple<Args..., void, void>>::type, response&>::value
                        , int>::type = 0)
                {
                    handler_ = req_handler_wrapper<Args...>(std::move(f));






                }

                template <typename ... Args>
                void set_(Func f, typename std::enable_if<
                        std::is_same<typename std::tuple_element<0, std::tuple<Args..., void>>::type, const request&>::value &&
                        std::is_same<typename std::tuple_element<1, std::tuple<Args..., void, void>>::type, response&>::value
                        , int>::type = 0)
                {
                    handler_ = std::move(f);
                }

                template <typename ... Args>
                struct handler_type_helper
                {
                    using type = std::function<void(const crow::request&, crow::response&, Args...)>;
                    using args_type = black_magic::S<typename black_magic::promote_t<Args>...>;
                };

                template <typename ... Args>
                struct handler_type_helper<const request&, Args...>
                {
                    using type = std::function<void(const crow::request&, crow::response&, Args...)>;
                    using args_type = black_magic::S<typename black_magic::promote_t<Args>...>;
                };

                template <typename ... Args>
                struct handler_type_helper<const request&, response&, Args...>
                {
                    using type = std::function<void(const crow::request&, crow::response&, Args...)>;
                    using args_type = black_magic::S<typename black_magic::promote_t<Args>...>;
                };

                typename handler_type_helper<ArgsWrapped...>::type handler_;

                void operator()(const request& req, response& res, const routing_params& params)
                {
                    detail::routing_handler_call_helper::call<
                        detail::routing_handler_call_helper::call_params<
                            decltype(handler_)>,
                        0, 0, 0, 0,
                        typename handler_type_helper<ArgsWrapped...>::args_type,
                        black_magic::S<>
                    >()(
                        detail::routing_handler_call_helper::call_params<
                            decltype(handler_)>
                        {handler_, params, req, res}
                   );
                }
            };

        }
    }

    class WebSocketRule : public BaseRule
    {
        using self_t = WebSocketRule;
    public:
        WebSocketRule(std::string rule)
            : BaseRule(std::move(rule))
        {
        }

        void validate() override
        {
        }

        void handle(const request&, response& res, const routing_params&) override
        {
            res = response(404);
            res.end();
        }

        void handle_upgrade(const request& req, response&, SocketAdaptor&& adaptor) override
        {
            new crow::websocket::Connection<SocketAdaptor>(req, std::move(adaptor), open_handler_, message_handler_, close_handler_, error_handler_, accept_handler_);
        }







        template <typename Func>
        self_t& onopen(Func f)
        {
            open_handler_ = f;
            return *this;
        }

        template <typename Func>
        self_t& onmessage(Func f)
        {
            message_handler_ = f;
            return *this;
        }

        template <typename Func>
        self_t& onclose(Func f)
        {
            close_handler_ = f;
            return *this;
        }

        template <typename Func>
        self_t& onerror(Func f)
        {
            error_handler_ = f;
            return *this;
        }

        template <typename Func>
        self_t& onaccept(Func f)
        {
            accept_handler_ = f;
            return *this;
        }

    protected:
        std::function<void(crow::websocket::connection&)> open_handler_;
        std::function<void(crow::websocket::connection&, const std::string&, bool)> message_handler_;
        std::function<void(crow::websocket::connection&, const std::string&)> close_handler_;
        std::function<void(crow::websocket::connection&)> error_handler_;
        std::function<bool(const crow::request&)> accept_handler_;
    };

    template <typename T>
    struct RuleParameterTraits
    {
        using self_t = T;
        WebSocketRule& websocket()
        {
            auto p =new WebSocketRule(((self_t*)this)->rule_);
            ((self_t*)this)->rule_to_upgrade_.reset(p);
            return *p;
        }

        self_t& name(std::string name) noexcept
        {
            ((self_t*)this)->name_ = std::move(name);
            return (self_t&)*this;
        }

        self_t& methods(HTTPMethod method)
        {
            ((self_t*)this)->methods_ = 1 << (int)method;
            return (self_t&)*this;
        }

        template <typename ... MethodArgs>
        self_t& methods(HTTPMethod method, MethodArgs ... args_method)
        {
            methods(args_method...);
            ((self_t*)this)->methods_ |= 1 << (int)method;
            return (self_t&)*this;
        }

    };

    class DynamicRule : public BaseRule, public RuleParameterTraits<DynamicRule>
    {
    public:

        DynamicRule(std::string rule)
            : BaseRule(std::move(rule))
        {
        }

        void validate() override
        {
            if (!erased_handler_)
            {
                throw std::runtime_error(name_ + (!name_.empty() ? ": " : "") + "no handler for url " + rule_);
            }
        }

        void handle(const request& req, response& res, const routing_params& params) override
        {
            erased_handler_(req, res, params);
        }

        template <typename Func>
        void operator()(Func f)
        {



            using function_t = utility::function_traits<Func>;

            erased_handler_ = wrap(std::move(f), black_magic::gen_seq<function_t::arity>());
        }







        template <typename Func, unsigned ... Indices>

        std::function<void(const request&, response&, const routing_params&)>
        wrap(Func f, black_magic::seq<Indices...>)
        {



            using function_t = utility::function_traits<Func>;

            if (!black_magic::is_parameter_tag_compatible(
                black_magic::get_parameter_tag_runtime(rule_.c_str()),
                black_magic::compute_parameter_tag_from_args_list<
                    typename function_t::template arg<Indices>...>::value))
            {
                throw std::runtime_error("route_dynamic: Handler type is mismatched with URL parameters: " + rule_);
            }
            auto ret = detail::routing_handler_call_helper::Wrapped<Func, typename function_t::template arg<Indices>...>();
            ret.template set_<
                typename function_t::template arg<Indices>...
            >(std::move(f));
            return ret;
        }

        template <typename Func>
        void operator()(std::string name, Func&& f)
        {
            name_ = std::move(name);
            (*this).template operator()<Func>(std::forward(f));
        }
    private:
        std::function<void(const request&, response&, const routing_params&)> erased_handler_;

    };

    template <typename ... Args>
    class TaggedRule : public BaseRule, public RuleParameterTraits<TaggedRule<Args...>>
    {
    public:
        using self_t = TaggedRule<Args...>;

        TaggedRule(std::string rule)
            : BaseRule(std::move(rule))
        {
        }

        void validate() override
        {
            if (!handler_)
            {
                throw std::runtime_error(name_ + (!name_.empty() ? ": " : "") + "no handler for url " + rule_);
            }
        }

        template <typename Func>
        typename std::enable_if<black_magic::CallHelper<Func, black_magic::S<Args...>>::value, void>::type
        operator()(Func&& f)
        {
            static_assert(black_magic::CallHelper<Func, black_magic::S<Args...>>::value ||
                black_magic::CallHelper<Func, black_magic::S<crow::request, Args...>>::value ,
                "Handler type is mismatched with URL parameters");
            static_assert(!std::is_same<void, decltype(f(std::declval<Args>()...))>::value,
                "Handler function cannot have void return type; valid return types: string, int, crow::resposne, crow::json::wvalue");

            handler_ = (



                [f]

                (const request&, response& res, Args ... args){
                    res = response(f(args...));
                    res.end();
                });
        }

        template <typename Func>
        typename std::enable_if<
            !black_magic::CallHelper<Func, black_magic::S<Args...>>::value &&
            black_magic::CallHelper<Func, black_magic::S<crow::request, Args...>>::value,
            void>::type
        operator()(Func&& f)
        {
            static_assert(black_magic::CallHelper<Func, black_magic::S<Args...>>::value ||
                black_magic::CallHelper<Func, black_magic::S<crow::request, Args...>>::value,
                "Handler type is mismatched with URL parameters");
            static_assert(!std::is_same<void, decltype(f(std::declval<crow::request>(), std::declval<Args>()...))>::value,
                "Handler function cannot have void return type; valid return types: string, int, crow::resposne, crow::json::wvalue");

            handler_ = (



                [f]

                (const crow::request& req, crow::response& res, Args ... args){
                    res = response(f(req, args...));
                    res.end();
                });
        }

        template <typename Func>
        typename std::enable_if<
            !black_magic::CallHelper<Func, black_magic::S<Args...>>::value &&
            !black_magic::CallHelper<Func, black_magic::S<crow::request, Args...>>::value,
            void>::type
        operator()(Func&& f)
        {
            static_assert(black_magic::CallHelper<Func, black_magic::S<Args...>>::value ||
                black_magic::CallHelper<Func, black_magic::S<crow::request, Args...>>::value ||
                black_magic::CallHelper<Func, black_magic::S<crow::request, crow::response&, Args...>>::value
                ,
                "Handler type is mismatched with URL parameters");
            static_assert(std::is_same<void, decltype(f(std::declval<crow::request>(), std::declval<crow::response&>(), std::declval<Args>()...))>::value,
                "Handler function with response argument should have void return type");

                handler_ = std::move(f);
        }

        template <typename Func>
        void operator()(std::string name, Func&& f)
        {
            name_ = std::move(name);
            (*this).template operator()<Func>(std::forward(f));
        }

        void handle(const request& req, response& res, const routing_params& params) override
        {
            detail::routing_handler_call_helper::call<
                detail::routing_handler_call_helper::call_params<
                    decltype(handler_)>,
                0, 0, 0, 0,
                black_magic::S<Args...>,
                black_magic::S<>
            >()(
                detail::routing_handler_call_helper::call_params<
                    decltype(handler_)>
                {handler_, params, req, res}
            );
        }

    private:
        std::function<void(const crow::request&, crow::response&, Args...)> handler_;

    };

    const int RULE_SPECIAL_REDIRECT_SLASH = 1;

    class Trie
    {
    public:
        struct Node
        {
            unsigned rule_index{};
            std::array<unsigned, (int)ParamType::MAX> param_childrens{};
            std::unordered_map<std::string, unsigned> children;

            bool IsSimpleNode() const
            {
                return
                    !rule_index &&
                    std::all_of(
                        std::begin(param_childrens),
                        std::end(param_childrens),
                        [](unsigned x){ return !x; });
            }
        };

        Trie() : nodes_(1)
        {
        }

private:
        void optimizeNode(Node* node)
        {
            for(auto x : node->param_childrens)
            {
                if (!x)
                    continue;
                Node* child = &nodes_[x];
                optimizeNode(child);
            }
            if (node->children.empty())
                return;
            bool mergeWithChild = true;
            for(auto& kv : node->children)
            {
                Node* child = &nodes_[kv.second];
                if (!child->IsSimpleNode())
                {
                    mergeWithChild = false;
                    break;
                }
            }
            if (mergeWithChild)
            {
                decltype(node->children) merged;
                for(auto& kv : node->children)
                {
                    Node* child = &nodes_[kv.second];
                    for(auto& child_kv : child->children)
                    {
                        merged[kv.first + child_kv.first] = child_kv.second;
                    }
                }
                node->children = std::move(merged);
                optimizeNode(node);
            }
            else
            {
                for(auto& kv : node->children)
                {
                    Node* child = &nodes_[kv.second];
                    optimizeNode(child);
                }
            }
        }

        void optimize()
        {
            optimizeNode(head());
        }

public:
        void validate()
        {
            if (!head()->IsSimpleNode())
                throw std::runtime_error("Internal error: Trie header should be simple!");
            optimize();
        }

        std::pair<unsigned, routing_params> find(const std::string& req_url, const Node* node = nullptr, unsigned pos = 0, routing_params* params = nullptr) const
        {
            routing_params empty;
            if (params == nullptr)
                params = &empty;

            unsigned found{};
            routing_params match_params;

            if (node == nullptr)
                node = head();
            if (pos == req_url.size())
                return {node->rule_index, *params};

            auto update_found = [&found, &match_params](std::pair<unsigned, routing_params>& ret)
            {
                if (ret.first && (!found || found > ret.first))
                {
                    found = ret.first;
                    match_params = std::move(ret.second);
                }
            };

            if (node->param_childrens[(int)ParamType::INT])
            {
                char c = req_url[pos];
                if ((c >= '0' && c <= '9') || c == '+' || c == '-')
                {
                    char* eptr;
                    errno = 0;
                    long long int value = strtoll(req_url.data()+pos, &eptr, 10);
                    if (errno != ERANGE && eptr != req_url.data()+pos)
                    {
                        params->int_params.push_back(value);
                        auto ret = find(req_url, &nodes_[node->param_childrens[(int)ParamType::INT]], eptr - req_url.data(), params);
                        update_found(ret);
                        params->int_params.pop_back();
                    }
                }
            }

            if (node->param_childrens[(int)ParamType::UINT])
            {
                char c = req_url[pos];
                if ((c >= '0' && c <= '9') || c == '+')
                {
                    char* eptr;
                    errno = 0;
                    unsigned long long int value = strtoull(req_url.data()+pos, &eptr, 10);
                    if (errno != ERANGE && eptr != req_url.data()+pos)
                    {
                        params->uint_params.push_back(value);
                        auto ret = find(req_url, &nodes_[node->param_childrens[(int)ParamType::UINT]], eptr - req_url.data(), params);
                        update_found(ret);
                        params->uint_params.pop_back();
                    }
                }
            }

            if (node->param_childrens[(int)ParamType::DOUBLE])
            {
                char c = req_url[pos];
                if ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')
                {
                    char* eptr;
                    errno = 0;
                    double value = strtod(req_url.data()+pos, &eptr);
                    if (errno != ERANGE && eptr != req_url.data()+pos)
                    {
                        params->double_params.push_back(value);
                        auto ret = find(req_url, &nodes_[node->param_childrens[(int)ParamType::DOUBLE]], eptr - req_url.data(), params);
                        update_found(ret);
                        params->double_params.pop_back();
                    }
                }
            }

            if (node->param_childrens[(int)ParamType::STRING])
            {
                size_t epos = pos;
                for(; epos < req_url.size(); epos ++)
                {
                    if (req_url[epos] == '/')
                        break;
                }

                if (epos != pos)
                {
                    params->string_params.push_back(req_url.substr(pos, epos-pos));
                    auto ret = find(req_url, &nodes_[node->param_childrens[(int)ParamType::STRING]], epos, params);
                    update_found(ret);
                    params->string_params.pop_back();
                }
            }

            if (node->param_childrens[(int)ParamType::PATH])
            {
                size_t epos = req_url.size();

                if (epos != pos)
                {
                    params->string_params.push_back(req_url.substr(pos, epos-pos));
                    auto ret = find(req_url, &nodes_[node->param_childrens[(int)ParamType::PATH]], epos, params);
                    update_found(ret);
                    params->string_params.pop_back();
                }
            }

            for(auto& kv : node->children)
            {
                const std::string& fragment = kv.first;
                const Node* child = &nodes_[kv.second];

                if (req_url.compare(pos, fragment.size(), fragment) == 0)
                {
                    auto ret = find(req_url, child, pos + fragment.size(), params);
                    update_found(ret);
                }
            }

            return {found, match_params};
        }

        void add(const std::string& url, unsigned rule_index)
        {
            unsigned idx{0};

            for(unsigned i = 0; i < url.size(); i ++)
            {
                char c = url[i];
                if (c == '<')
                {
                    static struct ParamTraits
                    {
                        ParamType type;
                        std::string name;
                    } paramTraits[] =
                    {
                        { ParamType::INT, "<int>" },
                        { ParamType::UINT, "<uint>" },
                        { ParamType::DOUBLE, "<float>" },
                        { ParamType::DOUBLE, "<double>" },
                        { ParamType::STRING, "<str>" },
                        { ParamType::STRING, "<string>" },
                        { ParamType::PATH, "<path>" },
                    };

                    for(auto& x:paramTraits)
                    {
                        if (url.compare(i, x.name.size(), x.name) == 0)
                        {
                            if (!nodes_[idx].param_childrens[(int)x.type])
                            {
                                auto new_node_idx = new_node();
                                nodes_[idx].param_childrens[(int)x.type] = new_node_idx;
                            }
                            idx = nodes_[idx].param_childrens[(int)x.type];
                            i += x.name.size();
                            break;
                        }
                    }

                    i --;
                }
                else
                {
                    std::string piece(&c, 1);
                    if (!nodes_[idx].children.count(piece))
                    {
                        auto new_node_idx = new_node();
                        nodes_[idx].children.emplace(piece, new_node_idx);
                    }
                    idx = nodes_[idx].children[piece];
                }
            }
            if (nodes_[idx].rule_index)
                throw std::runtime_error("handler already exists for " + url);
            nodes_[idx].rule_index = rule_index;
        }
    private:
        void debug_node_print(Node* n, int level)
        {
            for(int i = 0; i < (int)ParamType::MAX; i ++)
            {
                if (n->param_childrens[i])
                {
                    if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << std::string(2*level, ' ') ;
                    switch((ParamType)i)
                    {
                        case ParamType::INT:
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "<int>";
                            break;
                        case ParamType::UINT:
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "<uint>";
                            break;
                        case ParamType::DOUBLE:
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "<float>";
                            break;
                        case ParamType::STRING:
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "<str>";
                            break;
                        case ParamType::PATH:
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "<path>";
                            break;
                        default:
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "<ERROR>";
                            break;
                    }

                    debug_node_print(&nodes_[n->param_childrens[i]], level+1);
                }
            }
            for(auto& kv : n->children)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << std::string(2*level, ' ') << kv.first;
                debug_node_print(&nodes_[kv.second], level+1);
            }
        }

    public:
        void debug_print()
        {
            debug_node_print(head(), 0);
        }

    private:
        const Node* head() const
        {
            return &nodes_.front();
        }

        Node* head()
        {
            return &nodes_.front();
        }

        unsigned new_node()
        {
            nodes_.resize(nodes_.size()+1);
            return nodes_.size() - 1;
        }

        std::vector<Node> nodes_;
    };

    class Router
    {
    public:
        Router()
        {
        }

        DynamicRule& new_rule_dynamic(const std::string& rule)
        {
            auto ruleObject = new DynamicRule(rule);
            all_rules_.emplace_back(ruleObject);

            return *ruleObject;
        }

        template <uint64_t N>
        typename black_magic::arguments<N>::type::template rebind<TaggedRule>& new_rule_tagged(const std::string& rule)
        {
            using RuleT = typename black_magic::arguments<N>::type::template rebind<TaggedRule>;

            auto ruleObject = new RuleT(rule);
            all_rules_.emplace_back(ruleObject);

            return *ruleObject;
        }

        void internal_add_rule_object(const std::string& rule, BaseRule* ruleObject)
        {
            bool has_trailing_slash = false;
            std::string rule_without_trailing_slash;
            if (rule.size() > 1 && rule.back() == '/')
            {
                has_trailing_slash = true;
                rule_without_trailing_slash = rule;
                rule_without_trailing_slash.pop_back();
            }

            ruleObject->foreach_method([&](int method)
                    {
                        per_methods_[method].rules.emplace_back(ruleObject);
                        per_methods_[method].trie.add(rule, per_methods_[method].rules.size() - 1);



                        if (has_trailing_slash)
                        {
                            per_methods_[method].trie.add(rule_without_trailing_slash, RULE_SPECIAL_REDIRECT_SLASH);
                        }
                    });

        }

        void validate()
        {
            for(auto& rule:all_rules_)
            {
                if (rule)
                {
                    auto upgraded = rule->upgrade();
                    if (upgraded)
                        rule = std::move(upgraded);
                    rule->validate();
                    internal_add_rule_object(rule->rule(), rule.get());
                }
            }
            for(auto& per_method:per_methods_)
            {
                per_method.trie.validate();
            }
        }

        template <typename Adaptor>
        void handle_upgrade(const request& req, response& res, Adaptor&& adaptor)
        {
            if (req.method >= HTTPMethod::InternalMethodCount)
                return;
            auto& per_method = per_methods_[(int)req.method];
            auto& trie = per_method.trie;
            auto& rules = per_method.rules;

            auto found = trie.find(req.url);
            unsigned rule_index = found.first;
            if (!rule_index)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "Cannot match rules " << req.url << ' ' << method_name(req.method);
                res = response(404);
                res.end();
                return;
            }

            if (rule_index >= rules.size())
                throw std::runtime_error("Trie internal structure corrupted!");

            if (rule_index == RULE_SPECIAL_REDIRECT_SLASH)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << "Redirecting to a url with trailing slash: " << req.url;
                res = response(301);


                if (req.get_header_value("Host").empty())
                {
                    res.add_header("Location", req.url + "/");
                }
                else
                {
                    res.add_header("Location", "http://" + req.get_header_value("Host") + req.url + "/");
                }
                res.end();
                return;
            }

            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "Matched rule (upgrade) '" << rules[rule_index]->rule_ << "' " << (uint32_t)req.method << " / " << rules[rule_index]->get_methods();


            try
            {
                rules[rule_index]->handle_upgrade(req, res, std::move(adaptor));
            }
            catch(std::exception& e)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Error) crow::logger("ERROR   ", crow::LogLevel::Error) << "An uncaught exception occurred: " << e.what();
                res = response(500);
                res.end();
                return;
            }
            catch(...)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Error) crow::logger("ERROR   ", crow::LogLevel::Error) << "An uncaught exception occurred. The type was unknown so no information was available.";
                res = response(500);
                res.end();
                return;
            }
        }

        void handle(const request& req, response& res)
        {
            if (req.method >= HTTPMethod::InternalMethodCount)
                return;
            auto& per_method = per_methods_[(int)req.method];
            auto& trie = per_method.trie;
            auto& rules = per_method.rules;

            auto found = trie.find(req.url);

            unsigned rule_index = found.first;

            if (!rule_index)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "Cannot match rules " << req.url << ' ' << method_name(req.method);
                res = response(404);
                res.end();
                return;
            }

            if (rule_index >= rules.size())
                throw std::runtime_error("Trie internal structure corrupted!");

            if (rule_index == RULE_SPECIAL_REDIRECT_SLASH)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << "Redirecting to a url with trailing slash: " << req.url;
                res = response(301);


                if (req.get_header_value("Host").empty())
                {
                    res.add_header("Location", req.url + "/");
                }
                else
                {
                    res.add_header("Location", "http://" + req.get_header_value("Host") + req.url + "/");
                }
                res.end();
                return;
            }

            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "Matched rule '" << rules[rule_index]->rule_ << "' " << (uint32_t)req.method << " / " << rules[rule_index]->get_methods();


            try
            {
                rules[rule_index]->handle(req, res, found.second);
            }
            catch(std::exception& e)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Error) crow::logger("ERROR   ", crow::LogLevel::Error) << "An uncaught exception occurred: " << e.what();
                res = response(500);
                res.end();
                return;
            }
            catch(...)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Error) crow::logger("ERROR   ", crow::LogLevel::Error) << "An uncaught exception occurred. The type was unknown so no information was available.";
                res = response(500);
                res.end();
                return;
            }
        }

        void debug_print()
        {
            for(int i = 0; i < (int)HTTPMethod::InternalMethodCount; i ++)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << method_name((HTTPMethod)i);
                per_methods_[i].trie.debug_print();
            }
        }

    private:
        struct PerMethod
        {
            std::vector<BaseRule*> rules;
            Trie trie;


            PerMethod() : rules(2) {}
        };
        std::array<PerMethod, (int)HTTPMethod::InternalMethodCount> per_methods_;
        std::vector<std::unique_ptr<BaseRule>> all_rules_;
    };
}


       





namespace crow
{
    namespace detail
    {
        template <typename ... Middlewares>
        struct partial_context
            : public black_magic::pop_back<Middlewares...>::template rebind<partial_context>
            , public black_magic::last_element_type<Middlewares...>::type::context
        {
            using parent_context = typename black_magic::pop_back<Middlewares...>::template rebind<::crow::detail::partial_context>;
            template <int N>
            using partial = typename std::conditional<N == sizeof...(Middlewares)-1, partial_context, typename parent_context::template partial<N>>::type;

            template <typename T>
            typename T::context& get()
            {
                return static_cast<typename T::context&>(*this);
            }
        };

        template <>
        struct partial_context<>
        {
            template <int>
            using partial = partial_context;
        };

        template <int N, typename Context, typename Container, typename CurrentMW, typename ... Middlewares>
        bool middleware_call_helper(Container& middlewares, request& req, response& res, Context& ctx);

        template <typename ... Middlewares>
        struct context : private partial_context<Middlewares...>

        {
            template <int N, typename Context, typename Container>
            friend typename std::enable_if<(N==0)>::type after_handlers_call_helper(Container& middlewares, Context& ctx, request& req, response& res);
            template <int N, typename Context, typename Container>
            friend typename std::enable_if<(N>0)>::type after_handlers_call_helper(Container& middlewares, Context& ctx, request& req, response& res);

            template <int N, typename Context, typename Container, typename CurrentMW, typename ... Middlewares2>
            friend bool middleware_call_helper(Container& middlewares, request& req, response& res, Context& ctx);

            template <typename T>
            typename T::context& get()
            {
                return static_cast<typename T::context&>(*this);
            }

            template <int N>
            using partial = typename partial_context<Middlewares...>::template partial<N>;
        };
    }
}


       








namespace crow
{
    using namespace boost;
    using tcp = asio::ip::tcp;

    namespace detail
    {
        template <typename MW>
        struct check_before_handle_arity_3_const
        {
            template <typename T,
                void (T::*)(request&, response&, typename MW::context&) const = &T::before_handle
            >
            struct get
            { };
        };

        template <typename MW>
        struct check_before_handle_arity_3
        {
            template <typename T,
                void (T::*)(request&, response&, typename MW::context&) = &T::before_handle
            >
            struct get
            { };
        };

        template <typename MW>
        struct check_after_handle_arity_3_const
        {
            template <typename T,
                void (T::*)(request&, response&, typename MW::context&) const = &T::after_handle
            >
            struct get
            { };
        };

        template <typename MW>
        struct check_after_handle_arity_3
        {
            template <typename T,
                void (T::*)(request&, response&, typename MW::context&) = &T::after_handle
            >
            struct get
            { };
        };

        template <typename T>
        struct is_before_handle_arity_3_impl
        {
            template <typename C>
            static std::true_type f(typename check_before_handle_arity_3_const<T>::template get<C>*);

            template <typename C>
            static std::true_type f(typename check_before_handle_arity_3<T>::template get<C>*);

            template <typename C>
            static std::false_type f(...);

        public:
            static const bool value = decltype(f<T>(nullptr))::value;
        };

        template <typename T>
        struct is_after_handle_arity_3_impl
        {
            template <typename C>
            static std::true_type f(typename check_after_handle_arity_3_const<T>::template get<C>*);

            template <typename C>
            static std::true_type f(typename check_after_handle_arity_3<T>::template get<C>*);

            template <typename C>
            static std::false_type f(...);

        public:
            static const bool value = decltype(f<T>(nullptr))::value;
        };

        template <typename MW, typename Context, typename ParentContext>
        typename std::enable_if<!is_before_handle_arity_3_impl<MW>::value>::type
        before_handler_call(MW& mw, request& req, response& res, Context& ctx, ParentContext& )
        {
            mw.before_handle(req, res, ctx.template get<MW>(), ctx);
        }

        template <typename MW, typename Context, typename ParentContext>
        typename std::enable_if<is_before_handle_arity_3_impl<MW>::value>::type
        before_handler_call(MW& mw, request& req, response& res, Context& ctx, ParentContext& )
        {
            mw.before_handle(req, res, ctx.template get<MW>());
        }

        template <typename MW, typename Context, typename ParentContext>
        typename std::enable_if<!is_after_handle_arity_3_impl<MW>::value>::type
        after_handler_call(MW& mw, request& req, response& res, Context& ctx, ParentContext& )
        {
            mw.after_handle(req, res, ctx.template get<MW>(), ctx);
        }

        template <typename MW, typename Context, typename ParentContext>
        typename std::enable_if<is_after_handle_arity_3_impl<MW>::value>::type
        after_handler_call(MW& mw, request& req, response& res, Context& ctx, ParentContext& )
        {
            mw.after_handle(req, res, ctx.template get<MW>());
        }

        template <int N, typename Context, typename Container, typename CurrentMW, typename ... Middlewares>
        bool middleware_call_helper(Container& middlewares, request& req, response& res, Context& ctx)
        {
            using parent_context_t = typename Context::template partial<N-1>;
            before_handler_call<CurrentMW, Context, parent_context_t>(std::get<N>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));

            if (res.is_completed())
            {
                after_handler_call<CurrentMW, Context, parent_context_t>(std::get<N>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));
                return true;
            }

            if (middleware_call_helper<N+1, Context, Container, Middlewares...>(middlewares, req, res, ctx))
            {
                after_handler_call<CurrentMW, Context, parent_context_t>(std::get<N>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));
                return true;
            }

            return false;
        }

        template <int N, typename Context, typename Container>
        bool middleware_call_helper(Container& , request& , response& , Context& )
        {
            return false;
        }

        template <int N, typename Context, typename Container>
        typename std::enable_if<(N<0)>::type
        after_handlers_call_helper(Container& , Context& , request& , response& )
        {
        }

        template <int N, typename Context, typename Container>
        typename std::enable_if<(N==0)>::type after_handlers_call_helper(Container& middlewares, Context& ctx, request& req, response& res)
        {
            using parent_context_t = typename Context::template partial<N-1>;
            using CurrentMW = typename std::tuple_element<N, typename std::remove_reference<Container>::type>::type;
            after_handler_call<CurrentMW, Context, parent_context_t>(std::get<N>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));
        }

        template <int N, typename Context, typename Container>
        typename std::enable_if<(N>0)>::type after_handlers_call_helper(Container& middlewares, Context& ctx, request& req, response& res)
        {
            using parent_context_t = typename Context::template partial<N-1>;
            using CurrentMW = typename std::tuple_element<N, typename std::remove_reference<Container>::type>::type;
            after_handler_call<CurrentMW, Context, parent_context_t>(std::get<N>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));
            after_handlers_call_helper<N-1, Context, Container>(middlewares, ctx, req, res);
        }
    }




    template <typename Adaptor, typename Handler, typename ... Middlewares>
    class Connection
    {
    public:
        Connection(
            boost::asio::io_service& io_service,
            Handler* handler,
            const std::string& server_name,
            std::tuple<Middlewares...>* middlewares,
            std::function<std::string()>& get_cached_date_str_f,
            detail::dumb_timer_queue& timer_queue,
            typename Adaptor::context* adaptor_ctx_
            )
            : adaptor_(io_service, adaptor_ctx_),
            handler_(handler),
            parser_(this),
            server_name_(server_name),
            middlewares_(middlewares),
            get_cached_date_str(get_cached_date_str_f),
            timer_queue(timer_queue)
        {




        }

        ~Connection()
        {
            res.complete_request_handler_ = nullptr;
            cancel_deadline_timer();




        }

        decltype(std::declval<Adaptor>().raw_socket())& socket()
        {
            return adaptor_.raw_socket();
        }

        void start()
        {
            adaptor_.start([this](const boost::system::error_code& ec) {
                if (!ec)
                {
                    start_deadline();

                    do_read();
                }
                else
                {
                    check_destroy();
                }
            });
        }

        void handle_header()
        {

            if (parser_.check_version(1, 1) && parser_.headers.count("expect") && get_header_value(parser_.headers, "expect") == "100-continue")
            {
                buffers_.clear();
                static std::string expect_100_continue = "HTTP/1.1 100 Continue\r\n\r\n";
                buffers_.emplace_back(expect_100_continue.data(), expect_100_continue.size());
                do_write();
            }
        }

        void handle()
        {
            cancel_deadline_timer();
            bool is_invalid_request = false;
            add_keep_alive_ = false;

            req_ = std::move(parser_.to_request());
            request& req = req_;

            if (parser_.check_version(1, 0))
            {

                if (req.headers.count("connection"))
                {
                    if (boost::iequals(req.get_header_value("connection"),"Keep-Alive"))
                        add_keep_alive_ = true;
                }
                else
                    close_connection_ = true;
            }
            else if (parser_.check_version(1, 1))
            {

                if (req.headers.count("connection"))
                {
                    if (req.get_header_value("connection") == "close")
                        close_connection_ = true;
                    else if (boost::iequals(req.get_header_value("connection"),"Keep-Alive"))
                        add_keep_alive_ = true;
                }
                if (!req.headers.count("host"))
                {
                    is_invalid_request = true;
                    res = response(400);
                }
    if (parser_.is_upgrade())
    {
     if (req.get_header_value("upgrade") == "h2c")
     {


     }
                    else
                    {
                        close_connection_ = true;
                        handler_->handle_upgrade(req, res, std::move(adaptor_));
                        return;
                    }
    }
            }

            if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << "Request: " << boost::lexical_cast<std::string>(adaptor_.remote_endpoint()) << " " << this << " HTTP/" << parser_.http_major << "." << parser_.http_minor << ' '
             << method_name(req.method) << " " << req.url;


            need_to_call_after_handlers_ = false;
            if (!is_invalid_request)
            {
                res.complete_request_handler_ = []{};
                res.is_alive_helper_ = [this]()->bool{ return adaptor_.is_open(); };

                ctx_ = detail::context<Middlewares...>();
                req.middleware_context = (void*)&ctx_;
                req.io_service = &adaptor_.get_io_service();
                detail::middleware_call_helper<0, decltype(ctx_), decltype(*middlewares_), Middlewares...>(*middlewares_, req, res, ctx_);

                if (!res.completed_)
                {
                    res.complete_request_handler_ = [this]{ this->complete_request(); };
                    need_to_call_after_handlers_ = true;
                    handler_->handle(req, res);
                    if (add_keep_alive_)
                        res.set_header("connection", "Keep-Alive");
                }
                else
                {
                    complete_request();
                }
            }
            else
            {
                complete_request();
            }
        }

        void complete_request()
        {
            if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << "Response: " << this << ' ' << req_.raw_url << ' ' << res.code << ' ' << close_connection_;

            if (need_to_call_after_handlers_)
            {
                need_to_call_after_handlers_ = false;


                detail::after_handlers_call_helper<
                    ((int)sizeof...(Middlewares)-1),
                    decltype(ctx_),
                    decltype(*middlewares_)>
                (*middlewares_, ctx_, req_, res);
            }


            res.complete_request_handler_ = nullptr;

            if (!adaptor_.is_open())
            {


                return;
            }

            static std::unordered_map<int, std::string> statusCodes = {
                {200, "HTTP/1.1 200 OK\r\n"},
                {201, "HTTP/1.1 201 Created\r\n"},
                {202, "HTTP/1.1 202 Accepted\r\n"},
                {204, "HTTP/1.1 204 No Content\r\n"},

                {300, "HTTP/1.1 300 Multiple Choices\r\n"},
                {301, "HTTP/1.1 301 Moved Permanently\r\n"},
                {302, "HTTP/1.1 302 Moved Temporarily\r\n"},
                {304, "HTTP/1.1 304 Not Modified\r\n"},

                {400, "HTTP/1.1 400 Bad Request\r\n"},
                {401, "HTTP/1.1 401 Unauthorized\r\n"},
                {403, "HTTP/1.1 403 Forbidden\r\n"},
                {404, "HTTP/1.1 404 Not Found\r\n"},
                {413, "HTTP/1.1 413 Payload Too Large\r\n"},
                {422, "HTTP/1.1 422 Unprocessable Entity\r\n"},
                {429, "HTTP/1.1 429 Too Many Requests\r\n"},

                {500, "HTTP/1.1 500 Internal Server Error\r\n"},
                {501, "HTTP/1.1 501 Not Implemented\r\n"},
                {502, "HTTP/1.1 502 Bad Gateway\r\n"},
                {503, "HTTP/1.1 503 Service Unavailable\r\n"},
            };

            static std::string seperator = ": ";
            static std::string crlf = "\r\n";

            buffers_.clear();
            buffers_.reserve(4*(res.headers.size()+5)+3);

            if (res.body.empty() && res.json_value.t() == json::type::Object)
            {
                res.body = json::dump(res.json_value);
            }

            if (!statusCodes.count(res.code))
                res.code = 500;
            {
                auto& status = statusCodes.find(res.code)->second;
                buffers_.emplace_back(status.data(), status.size());
            }

            if (res.code >= 400 && res.body.empty())
                res.body = statusCodes[res.code].substr(9);

            for(auto& kv : res.headers)
            {
                buffers_.emplace_back(kv.first.data(), kv.first.size());
                buffers_.emplace_back(seperator.data(), seperator.size());
                buffers_.emplace_back(kv.second.data(), kv.second.size());
                buffers_.emplace_back(crlf.data(), crlf.size());

            }

            if (!res.headers.count("content-length"))
            {
                content_length_ = std::to_string(res.body.size());
                static std::string content_length_tag = "Content-Length: ";
                buffers_.emplace_back(content_length_tag.data(), content_length_tag.size());
                buffers_.emplace_back(content_length_.data(), content_length_.size());
                buffers_.emplace_back(crlf.data(), crlf.size());
            }
            if (!res.headers.count("server"))
            {
                static std::string server_tag = "Server: ";
                buffers_.emplace_back(server_tag.data(), server_tag.size());
                buffers_.emplace_back(server_name_.data(), server_name_.size());
                buffers_.emplace_back(crlf.data(), crlf.size());
            }
            if (!res.headers.count("date"))
            {
                static std::string date_tag = "Date: ";
                date_str_ = get_cached_date_str();
                buffers_.emplace_back(date_tag.data(), date_tag.size());
                buffers_.emplace_back(date_str_.data(), date_str_.size());
                buffers_.emplace_back(crlf.data(), crlf.size());
            }
            if (add_keep_alive_)
            {
                static std::string keep_alive_tag = "Connection: Keep-Alive";
                buffers_.emplace_back(keep_alive_tag.data(), keep_alive_tag.size());
                buffers_.emplace_back(crlf.data(), crlf.size());
            }

            buffers_.emplace_back(crlf.data(), crlf.size());
            res_body_copy_.swap(res.body);
            buffers_.emplace_back(res_body_copy_.data(), res_body_copy_.size());

            do_write();

            if (need_to_start_read_after_complete_)
            {
                need_to_start_read_after_complete_ = false;
                start_deadline();
                do_read();
            }
        }

    private:
        void do_read()
        {

            is_reading = true;
            adaptor_.socket().async_read_some(boost::asio::buffer(buffer_),
                [this](const boost::system::error_code& ec, std::size_t bytes_transferred)
                {
                    bool error_while_reading = true;
                    if (!ec)
                    {
                        bool ret = parser_.feed(buffer_.data(), bytes_transferred);
                        if (ret && adaptor_.is_open())
                        {
                            error_while_reading = false;
                        }
                    }

                    if (error_while_reading)
                    {
                        cancel_deadline_timer();
                        parser_.done();
                        adaptor_.close();
                        is_reading = false;
                        if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " from read(1)";
                        check_destroy();
                    }
                    else if (close_connection_)
                    {
                        cancel_deadline_timer();
                        parser_.done();
                        is_reading = false;
                        check_destroy();

                    }
                    else if (!need_to_call_after_handlers_)
                    {
                        start_deadline();
                        do_read();
                    }
                    else
                    {

                        need_to_start_read_after_complete_ = true;
                    }
                });
        }

        void do_write()
        {

            is_writing = true;
            boost::asio::async_write(adaptor_.socket(), buffers_,
                [&](const boost::system::error_code& ec, std::size_t )
                {
                    is_writing = false;
                    res.clear();
                    res_body_copy_.clear();
                    if (!ec)
                    {
                        if (close_connection_)
                        {
                            adaptor_.close();
                            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " from write(1)";
                            check_destroy();
                        }
                    }
                    else
                    {
                        if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " from write(2)";
                        check_destroy();
                    }
                });
        }

        void check_destroy()
        {
            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " is_reading " << is_reading << " is_writing " << is_writing;
            if (!is_reading && !is_writing)
            {
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " delete (idle) ";
                delete this;
            }
        }

        void cancel_deadline_timer()
        {
            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " timer cancelled: " << timer_cancel_key_.first << ' ' << timer_cancel_key_.second;
            timer_queue.cancel(timer_cancel_key_);
        }

        void start_deadline( )
        {
            cancel_deadline_timer();

            timer_cancel_key_ = timer_queue.add([this]
            {
                if (!adaptor_.is_open())
                {
                    return;
                }
                adaptor_.close();
            });
            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << this << " timer added: " << timer_cancel_key_.first << ' ' << timer_cancel_key_.second;
        }

    private:
        Adaptor adaptor_;
        Handler* handler_;

        boost::array<char, 4096> buffer_;

        HTTPParser<Connection> parser_;
        request req_;
        response res;

        bool close_connection_ = false;

        const std::string& server_name_;
        std::vector<boost::asio::const_buffer> buffers_;

        std::string content_length_;
        std::string date_str_;
        std::string res_body_copy_;


        detail::dumb_timer_queue::key timer_cancel_key_;

        bool is_reading{};
        bool is_writing{};
        bool need_to_call_after_handlers_{};
        bool need_to_start_read_after_complete_{};
        bool add_keep_alive_{};

        std::tuple<Middlewares...>* middlewares_;
        detail::context<Middlewares...> ctx_;

        std::function<std::string()>& get_cached_date_str;
        detail::dumb_timer_queue& timer_queue;
    };

}


       


















namespace crow
{
    using namespace boost;
    using tcp = asio::ip::tcp;

    template <typename Handler, typename Adaptor = SocketAdaptor, typename ... Middlewares>
    class Server
    {
    public:
    Server(Handler* handler, std::string bindaddr, uint16_t port, std::tuple<Middlewares...>* middlewares = nullptr, uint16_t concurrency = 1, typename Adaptor::context* adaptor_ctx = nullptr)
            : acceptor_(io_service_, tcp::endpoint(boost::asio::ip::address::from_string(bindaddr), port)),
            signals_(io_service_, SIGINT, SIGTERM),
            tick_timer_(io_service_),
            handler_(handler),
            concurrency_(concurrency),
            port_(port),
            bindaddr_(bindaddr),
            middlewares_(middlewares),
            adaptor_ctx_(adaptor_ctx)
        {
        }

        void set_tick_function(std::chrono::milliseconds d, std::function<void()> f)
        {
            tick_interval_ = d;
            tick_function_ = f;
        }

        void on_tick()
        {
            tick_function_();
            tick_timer_.expires_from_now(boost::posix_time::milliseconds(tick_interval_.count()));
            tick_timer_.async_wait([this](const boost::system::error_code& ec)
                    {
                        if (ec)
                            return;
                        on_tick();
                    });
        }

        void run()
        {
            if (concurrency_ < 0)
                concurrency_ = 1;

            for(int i = 0; i < concurrency_; i++)
                io_service_pool_.emplace_back(new boost::asio::io_service());
            get_cached_date_str_pool_.resize(concurrency_);
            timer_queue_pool_.resize(concurrency_);

            std::vector<std::future<void>> v;
            std::atomic<int> init_count(0);
            for(uint16_t i = 0; i < concurrency_; i ++)
                v.push_back(
                        std::async(std::launch::async, [this, i, &init_count]{


                            auto last = std::chrono::steady_clock::now();

                            std::string date_str;
                            auto update_date_str = [&]
                            {
                                auto last_time_t = time(0);
                                tm my_tm;




                                gmtime_r(&last_time_t, &my_tm);

                                date_str.resize(100);
                                size_t date_str_sz = strftime(&date_str[0], 99, "%a, %d %b %Y %H:%M:%S GMT", &my_tm);
                                date_str.resize(date_str_sz);
                            };
                            update_date_str();
                            get_cached_date_str_pool_[i] = [&]()->std::string
                            {
                                if (std::chrono::steady_clock::now() - last >= std::chrono::seconds(1))
                                {
                                    last = std::chrono::steady_clock::now();
                                    update_date_str();
                                }
                                return date_str;
                            };


                            detail::dumb_timer_queue timer_queue;
                            timer_queue_pool_[i] = &timer_queue;

                            timer_queue.set_io_service(*io_service_pool_[i]);
                            boost::asio::deadline_timer timer(*io_service_pool_[i]);
                            timer.expires_from_now(boost::posix_time::seconds(1));

                            std::function<void(const boost::system::error_code& ec)> handler;
                            handler = [&](const boost::system::error_code& ec){
                                if (ec)
                                    return;
                                timer_queue.process();
                                timer.expires_from_now(boost::posix_time::seconds(1));
                                timer.async_wait(handler);
                            };
                            timer.async_wait(handler);

                            init_count ++;
                            while(1)
                            {
                                try
                                {
                                    if (io_service_pool_[i]->run() == 0)
                                    {

                                        break;
                                    }
                                } catch(std::exception& e)
                                {
                                    if (crow::logger::get_current_log_level() <= crow::LogLevel::Error) crow::logger("ERROR   ", crow::LogLevel::Error) << "Worker Crash: An uncaught exception occurred: " << e.what();
                                }
                            }
                        }));

            if (tick_function_ && tick_interval_.count() > 0)
            {
                tick_timer_.expires_from_now(boost::posix_time::milliseconds(tick_interval_.count()));
                tick_timer_.async_wait([this](const boost::system::error_code& ec)
                        {
                            if (ec)
                                return;
                            on_tick();
                        });
            }

            if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << server_name_ << " server is running at " << bindaddr_ <<":" << port_
                          << " using " << concurrency_ << " threads";
            if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << "Call `app.loglevel(crow::LogLevel::Warning)` to hide Info level logs.";

            signals_.async_wait(
                [&](const boost::system::error_code& , int ){
                    stop();
                });

            while(concurrency_ != init_count)
                std::this_thread::yield();

            do_accept();

            std::thread([this]{
                io_service_.run();
                if (crow::logger::get_current_log_level() <= crow::LogLevel::Info) crow::logger("INFO    ", crow::LogLevel::Info) << "Exiting.";
            }).join();
        }

        void stop()
        {
            io_service_.stop();
            for(auto& io_service:io_service_pool_)
                io_service->stop();
        }

    private:
        asio::io_service& pick_io_service()
        {

            roundrobin_index_++;
            if (roundrobin_index_ >= io_service_pool_.size())
                roundrobin_index_ = 0;
            return *io_service_pool_[roundrobin_index_];
        }

        void do_accept()
        {
            asio::io_service& is = pick_io_service();
            auto p = new Connection<Adaptor, Handler, Middlewares...>(
                is, handler_, server_name_, middlewares_,
                get_cached_date_str_pool_[roundrobin_index_], *timer_queue_pool_[roundrobin_index_],
                adaptor_ctx_);
            acceptor_.async_accept(p->socket(),
                [this, p, &is](boost::system::error_code ec)
                {
                    if (!ec)
                    {
                        is.post([p]
                        {
                            p->start();
                        });
                    }
                    else
                    {
                        delete p;
                    }
                    do_accept();
                });
        }

    private:
        asio::io_service io_service_;
        std::vector<std::unique_ptr<asio::io_service>> io_service_pool_;
        std::vector<detail::dumb_timer_queue*> timer_queue_pool_;
        std::vector<std::function<std::string()>> get_cached_date_str_pool_;
        tcp::acceptor acceptor_;
        boost::asio::signal_set signals_;
        boost::asio::deadline_timer tick_timer_;

        Handler* handler_;
        uint16_t concurrency_{1};
        std::string server_name_ = "Crow/0.1";
        uint16_t port_;
        std::string bindaddr_;
        unsigned int roundrobin_index_{};

        std::chrono::milliseconds tick_interval_;
        std::function<void()> tick_function_;

        std::tuple<Middlewares...>* middlewares_;





        typename Adaptor::context* adaptor_ctx_;
    };
}


       











namespace crow
{



    template <typename ... Middlewares>
    class Crow
    {
    public:
        using self_t = Crow;
        using server_t = Server<Crow, SocketAdaptor, Middlewares...>;



        Crow()
        {
        }

  template <typename Adaptor>
        void handle_upgrade(const request& req, response& res, Adaptor&& adaptor)
        {
            router_.handle_upgrade(req, res, adaptor);
        }

        void handle(const request& req, response& res)
        {
            router_.handle(req, res);
        }

        DynamicRule& route_dynamic(std::string&& rule)
        {
            return router_.new_rule_dynamic(std::move(rule));
        }

        template <uint64_t Tag>
        auto route(std::string&& rule)
            -> typename std::result_of<decltype(&Router::new_rule_tagged<Tag>)(Router, std::string&&)>::type
        {
            return router_.new_rule_tagged<Tag>(std::move(rule));
        }

        self_t& port(std::uint16_t port)
        {
            port_ = port;
            return *this;
        }

        self_t& bindaddr(std::string bindaddr)
        {
            bindaddr_ = bindaddr;
            return *this;
        }

        self_t& multithreaded()
        {
            return concurrency(std::thread::hardware_concurrency());
        }

        self_t& concurrency(std::uint16_t concurrency)
        {
            if (concurrency < 1)
                concurrency = 1;
            concurrency_ = concurrency;
            return *this;
        }

        void validate()
        {
            router_.validate();
        }

        void notify_server_start()
        {
            std::unique_lock<std::mutex> lock(start_mutex_);
            server_started_ = true;
            cv_started_.notify_all();
        }

        void run()
        {
            validate();

            {
                server_ = std::move(std::unique_ptr<server_t>(new server_t(this, bindaddr_, port_, &middlewares_, concurrency_, nullptr)));
                server_->set_tick_function(tick_interval_, tick_function_);
                notify_server_start();
                server_->run();
            }
        }

        void stop()
        {







            {
                server_->stop();
            }
        }

        void debug_print()
        {
            if (crow::logger::get_current_log_level() <= crow::LogLevel::Debug) crow::logger("DEBUG   ", crow::LogLevel::Debug) << "Routing:";
            router_.debug_print();
        }

        self_t& loglevel(crow::LogLevel level)
        {
            crow::logger::setLogLevel(level);
            return *this;
        }

        template <typename T, typename ... Remain>
        self_t& ssl_file(T&&, Remain&&...)
        {

            static_assert(

                    std::is_base_of<T, void>::value,
                    "Define CROW_ENABLE_SSL to enable ssl support.");
            return *this;
        }

        template <typename T>
        self_t& ssl(T&&)
        {

            static_assert(

                    std::is_base_of<T, void>::value,
                    "Define CROW_ENABLE_SSL to enable ssl support.");
            return *this;
        }



        using context_t = detail::context<Middlewares...>;
        template <typename T>
        typename T::context& get_context(const request& req)
        {
            static_assert(black_magic::contains<T, Middlewares...>::value, "App doesn't have the specified middleware type.");
            auto& ctx = *reinterpret_cast<context_t*>(req.middleware_context);
            return ctx.template get<T>();
        }

        template <typename T>
        T& get_middleware()
        {
            return utility::get_element_by_type<T, Middlewares...>(middlewares_);
        }

        template <typename Duration, typename Func>
        self_t& tick(Duration d, Func f) {
            tick_interval_ = std::chrono::duration_cast<std::chrono::milliseconds>(d);
            tick_function_ = f;
            return *this;
        }

        void wait_for_server_start()
        {
            std::unique_lock<std::mutex> lock(start_mutex_);
            if (server_started_)
                return;
            cv_started_.wait(lock);
        }

    private:
        uint16_t port_ = 80;
        uint16_t concurrency_ = 1;
        std::string bindaddr_ = "0.0.0.0";
        Router router_;

        std::chrono::milliseconds tick_interval_;
        std::function<void()> tick_function_;

        std::tuple<Middlewares...> middlewares_;




        std::unique_ptr<server_t> server_;

        bool server_started_{false};
        std::condition_variable cv_started_;
        std::mutex start_mutex_;
    };
    template <typename ... Middlewares>
    using App = Crow<Middlewares...>;
    using SimpleApp = Crow<>;
}





int main(int argc, char *argv[]) {
    crow::SimpleApp app;

    app.route<crow::black_magic::get_parameter_tag("/""index.html")>("/""index.html")([](const crow::request & , crow::response &res) {
        res.add_header("Content-Type", "text/html; charset=UTF-8");
        res.add_header("ETag", "\"md5/3b0c2c10e5f8348513208ebd121e4d82\"");
        res.add_header("Last-Modified", "Sat, 22 Aug 2026 21:16:03 GMT");
        res.write(std::string(R"***(<!DOCTYPE html>
<html lang="en-us">
<head>
	<meta http-equiv="X-UA-Compatible" content="IE=Edge">
	<meta charset="UTF-8">
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>TaiLing.cc</title>
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
	<link rel="stylesheet" href="css/theme.css">
	<style>
.header {
	position: fixed;
	width: 100%;
	height: 100%;
	background-image: url(images/header/headerbg.jpg);
	background-size: 100% 100%;
}

p.console-fontsize {
	font-size: 20px;
}

@media screen and (max-width: 800px) {
	p.console-fontsize {
		font-size: 16px;
	}
}
	</style>
</head>
<body>
	<div class="header"></div>
	<div class="section type-1 big splash">
		<div class="container">
			<div class="splash-block" style="text-align: center;">
				<div class="centered" style="width: 90%; padding-top: 50px; padding-bottom: 50px;">
					<div class="container">
						<div>
							<h1>TaiLing.cc</h1>
							<p>is compiled from single C++ file,</p>
							<p>and produces the sourcecode itself.</p>
						</div>
						<div class="row">
							<div class="col-1"></div>
							<div class="col-10" style="background: #000; padding: 30px; font-family: monospace, consolas; color: #909090; text-align: left; overflow: auto; border: 5px solid #909090;">
								<p class="console-fontsize">$ curl <a class="path-to-cc" href="tailing.cc">http://tailing.cc/tailing.cc</a> -o tailing.cc</p>
								<p class="console-fontsize">$ sudo apt install libboost-system-dev</p>
								<p class="console-fontsize">$ g++ tailing.cc -std=c++11 -O2 -lpthread -lboost_system -orun</p>
								<p class="console-fontsize">$ rm tailing.cc <font color="#606060"># Take it easy, you can soon download it from localhost</font></p>
								<p class="console-fontsize">$ ./run 8888</p>
								<p class="console-fontsize">Then, you can browse <a href="http://localhost:8888/">http://localhost:8888/</a></p>
							</div>
						</div>
						<div style="padding-top: 20px;">
							<a href="http://tailing.cc/" class="btn btn-outline btn-lg">Homepage</a>
							&nbsp;
							<a href="https://github.com/yuantailing/tailing.cc" class="btn btn-outline btn-lg">Github</a>
						</div>
						<p style="font-size: 14px; padding-top: 20px;">&copy; <script>document.write((new Date()).getFullYear());</script> <a style="color: #fff;" href="https://github.com/yuantailing">Tailing Yuan</a></p>
					</div>
				</div>
			</div>
		</div>
	</div>
	<script>
/**/;(function() {
	'use strict';
	var pos = location.href.lastIndexOf('/');
	var path_to_cc = location.href.slice(0, pos + 1) + 'tailing.cc';
	var elems = document.getElementsByClassName('path-to-cc');
	for (var i = 0; i < elems.length; i++) {
		elems[i].textContent = path_to_cc;
	}
})();
	</script>
</body>
</html>
)***", 2992));
        res.end();
    });

    app.route<crow::black_magic::get_parameter_tag("/""")>("/""")([](const crow::request & , crow::response &res) {
        res.add_header("Content-Type", "text/html; charset=UTF-8");
        res.add_header("ETag", "\"md5/3b0c2c10e5f8348513208ebd121e4d82\"");
        res.add_header("Last-Modified", "Sat, 22 Aug 2026 21:16:03 GMT");
        res.write(std::string(R"***(<!DOCTYPE html>
<html lang="en-us">
<head>
	<meta http-equiv="X-UA-Compatible" content="IE=Edge">
	<meta charset="UTF-8">
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>TaiLing.cc</title>
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
	<link rel="stylesheet" href="css/theme.css">
	<style>
.header {
	position: fixed;
	width: 100%;
	height: 100%;
	background-image: url(images/header/headerbg.jpg);
	background-size: 100% 100%;
}

p.console-fontsize {
	font-size: 20px;
}

@media screen and (max-width: 800px) {
	p.console-fontsize {
		font-size: 16px;
	}
}
	</style>
</head>
<body>
	<div class="header"></div>
	<div class="section type-1 big splash">
		<div class="container">
			<div class="splash-block" style="text-align: center;">
				<div class="centered" style="width: 90%; padding-top: 50px; padding-bottom: 50px;">
					<div class="container">
						<div>
							<h1>TaiLing.cc</h1>
							<p>is compiled from single C++ file,</p>
							<p>and produces the sourcecode itself.</p>
						</div>
						<div class="row">
							<div class="col-1"></div>
							<div class="col-10" style="background: #000; padding: 30px; font-family: monospace, consolas; color: #909090; text-align: left; overflow: auto; border: 5px solid #909090;">
								<p class="console-fontsize">$ curl <a class="path-to-cc" href="tailing.cc">http://tailing.cc/tailing.cc</a> -o tailing.cc</p>
								<p class="console-fontsize">$ sudo apt install libboost-system-dev</p>
								<p class="console-fontsize">$ g++ tailing.cc -std=c++11 -O2 -lpthread -lboost_system -orun</p>
								<p class="console-fontsize">$ rm tailing.cc <font color="#606060"># Take it easy, you can soon download it from localhost</font></p>
								<p class="console-fontsize">$ ./run 8888</p>
								<p class="console-fontsize">Then, you can browse <a href="http://localhost:8888/">http://localhost:8888/</a></p>
							</div>
						</div>
						<div style="padding-top: 20px;">
							<a href="http://tailing.cc/" class="btn btn-outline btn-lg">Homepage</a>
							&nbsp;
							<a href="https://github.com/yuantailing/tailing.cc" class="btn btn-outline btn-lg">Github</a>
						</div>
						<p style="font-size: 14px; padding-top: 20px;">&copy; <script>document.write((new Date()).getFullYear());</script> <a style="color: #fff;" href="https://github.com/yuantailing">Tailing Yuan</a></p>
					</div>
				</div>
			</div>
		</div>
	</div>
	<script>
/**/;(function() {
	'use strict';
	var pos = location.href.lastIndexOf('/');
	var path_to_cc = location.href.slice(0, pos + 1) + 'tailing.cc';
	var elems = document.getElementsByClassName('path-to-cc');
	for (var i = 0; i < elems.length; i++) {
		elems[i].textContent = path_to_cc;
	}
})();
	</script>
</body>
</html>
)***", 2992));
        res.end();
    });

    app.route<crow::black_magic::get_parameter_tag("/""images/header/headerbg.jpg")>("/""images/header/headerbg.jpg")([](const crow::request & , crow::response &res) {
        res.add_header("Content-Type", "image/jpeg; charset=UTF-8");
        res.add_header("ETag", "\"md5/97dc221ad1c748626146af95ba098fad\"");
        res.add_header("Last-Modified", "Sat, 22 Aug 2026 21:16:03 GMT");
        res.write(std::string(R"***(ÿØÿà JFIF      ÿş ;CREATOR: gd-jpeg v1.0 (using IJG JPEG v62), quality = 95
ÿÛ C 			





	


ÿÛ C


















































ÿÀ 8€" ÿÄ           	
ÿÄ µ   } !1AQa"q2‘¡#B±ÁRÑğ$3br‚	
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyzƒ„…†‡ˆ‰Š’“”•–—˜™š¢£¤¥¦§¨©ª²³´µ¶·¸¹ºÂÃÄÅÆÇÈÉÊÒÓÔÕÖ×ØÙÚáâãäåæçèéêñòóôõö÷øùúÿÄ        	
ÿÄ µ  w !1AQaq"2B‘¡±Á	#3RğbrÑ
$4á%ñ&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz‚ƒ„…†‡ˆ‰Š’“”•–—˜™š¢£¤¥¦§¨©ª²³´µ¶·¸¹ºÂÃÄÅÆÇÈÉÊÒÓÔÕÖ×ØÙÚâãäåæçèéêòóôõö÷øùúÿÚ   ? õ–ryÍ0ÈG8ıj)%¡üª6‘#5şvÆ™ş2ûNeÿ jšÒœsP†c×ùÑÒµŒ5-QcÚ^0ô¦3úšk68šÎ{šÑDÑP$Ñ¿JL÷ÍG½}iàV±Š+êìsKøS^BO˜I!#8+úÖª#TıíMg÷Í0ã° ät­#Õ¼çŠ7·­F]³IZ(š*DŞgµ4Ë×š`Ç¦iNp)***""\r" R"***(iÜ¯b‡ dšo™íLç¯Z2ßİıkU½ˆ­!'ši˜ãšS¸ŒcFÇñZÅCÄ™íJ²ãÚ¡ IÆhÜİÍl¢Uc&{æš\öâ£.qéM2œõ5¢…ªİØœfšd#©¦jBIêkEıŠe'ŠO3Ú˜X
nòzÑD¯dI¹½h,Şµ›şÕ4¾{Vª(¥I²GõNi77­%j’FŠ’BîcŞšÌGoÆ”ä)***""\r" R"***(5”Iª[–©¡¤“Ö“Üâ†8ïÂš	 Ö©*k¨nnæ‚ÙíIAëZ$Z¦‚˜ızÒ•áZkqŠÒ)”¨ˆÍÎ	éÚšX((sÀ¦±ÛÚº"U!i`´İíëM/ÏÖÑF‘¦<H@À¦4„õ4Òõ£czV±‰¢§qLœt¦NM)Vš@	8¤R-SaLcóSÊ2ÔÓñ­bihŒE-#.îô W ÍZFŠšHì1LrAÆ{RòAÊş¦•=—õ­–ÅªlJ(9¦[&®%¨0$’)»ÛÖ•—9¦0Ü1[Å¨{Š<Ïj‰F‡?>¶Š-Bãš@GçLgb	#>8ÒIëZ$‘ª¦(?6ãCÉÇJJG$+E±\ˆa99¢´„Ğâ©\®FÁ›oj@ãÑåûÒ2ã íV·*0Ô“Q¹$‘=)ÌÛN1M$±ÇcÚµQ5å'Í4©=[ô©w?•4ğN*Ö…(‘‘ƒŠ(n§ëEhŠå¸°û¿­#6M9ºe4ËQ£4gµ+ıÓL«M$+ÉÇJŒ)***""\r" R"***(Ç­?gµI¢ÔF0  M%=—wzP tI³E¡ 8Ç$gµJëHíQ6îİ1ZÅ¶Z‚I»æÛŠZ+X¦_(QL`A$ô•²RJ:R/Aô¥­j(iJi$õ§Hp3Q—ÈÆ*ÕÍ}¹ştß3qÆê)nÍj·)@ZG$ƒIåûÒ2íïZ äw‘›b—¥5Á' v­c¹j#i¥ğqŠu4¦NsZ¦Ë³NNh¥ îÚ( MkBQK¹½i+E;”bî+øÒ1$Õ!éQ°=)***""\r" R"***(m$G“œæ”±<JPÁÍ78Åh¤Ù|¡M~Ÿ?iÚ8ç½Ò¶Å¤ìEEJT¢˜à‚´‹H¥6˜ı
yuŒ»s[E¢â¬2ŠRŒN=iB95f‰\mFİOÖ¤*WéšFŒôªLÖ6E;`Å&Æô­“ÔÛq	ÀÍ4’TœS¨­)***""\r" R"***(aª:¿iÔP=)***""\r" R"***(1ˆÓñ¦‘€zÓûâ€¤œM;Æ$`qƒGzw—Ï_Òÿ ¥Z’; †2î9Í Ny5*£¦¿Ş4ù™ÑG·-K³Ş#9¥ûÕ¦o¢?/œçô¥^ƒéO;šB»pZw7…Ä¤n‡éNØpsFÖâªçT6"'ï/ŞŸ°ã#ò !>Ôs£x¡»~]¹¡WiÎjE'Ö‘£ ñG:: †ÑJTã…ıh¼Ôs&t@NôSÕv´´“:#¡3ÚŸtS€ÉÅ9PçƒCfğdc§ãKRlÚÄÓTÄ‘Jèë‚RS|¿zxRFj”‘Ò–¢QíN
GUıiÄÓçFñ½ÈÈ àĞsRícÚ”FM
gLH dŠruü*O/ßô¥UÇ9§ÎÍãa”õ'4å]İèÙÔçµR•Íàìô›ÿ -)ÔSæ:#¨Q“´ä\sN ã>½é©jtE)***""\r" R"***(UÇ9íN§"ãœÓª”µ7Š°P	 ÓÂíÍ$Îˆ\eóíHP1ÎjÓ¹ÑDO½O¤XÎr)qÎ)1İÚ‚	•—wz¸tÉƒÚ•	#$Ò€HÎ(^¢ô:¢Â„àÒÉÎiÈ½4ù¥r)9ëNØ1×ñ¥TÁëTtB@‘NSÁÔ‚=½_zzÆyÅP‘ÉÈö¦àç¥hÈ4Öuê“: ì4&sJà‘À¥ z
£x²=»1Ò€vR{Rwü)İc9çæ•—wzR›†qM=N˜=Hé®¿Ä*UF3MprN8õ«NÇT]Æ®@æ”R…$ô¥ã¿éTÍâÆÓ× úR¨$`Q³ojw6ŒµOQíCõü(1ã'=¨ ¯ ÕEQcKrjnv÷©#­GL$Èğs¶Š—a 0ü©=¨:£-À'¥9;Ó»âŠ´kR”"“¥_1Ò¤8Ïjr7ğĞ£'q4ğ›€9«½Ñ¬d7v#ñ¡G;ëN+‘Buü)£¢2aó(Ï­;vàx¡z¥-lt)1¥øÆ)¦œë})¦šW:"õ
F;FqA¥å@#4ÕˆHk´J:
?Ò–­ntBVaF{P=(Œõ<Sº:¡!1éE)C(HçŠZ˜ƒšPüdŠP6€)qŸZ±´f4/;ƒuö§ch ’)Á23šÒ-Ælh,8­	á½)ê¸¥ µI™ŒŸºxô£g?)©iÈÅRgDfÆÍğ¹:Òl¹ªæGD*1¤ç=)Ä•êsJ">œSÖCI´uÂ Şh©'°Å4ÄGZkc¢5ç4äoáÅ'”:çñÅ/–O¦tBwxÎ¥¸¤S‚p8¦¬tÆh@{ŠE"#b#=hˆLõ§by¨İÎ3NrOzÿ ÿ ,ãËÊ¢*¿½)—Œf£¤v­T)***""\r" R"***(#Dy“ĞSds R3 8"šX‘ŠµEEæ{S]ÁêqI»ı“ùS\ç’+XÓ¥qÛ‡÷5¤ ã==©…È<*BI95¢¦5G]‡ù™çu4Êı¦Ò7Nÿ …kX¥Dvöõ£{zÓ?ïª]ßìŸÊ­E”¨®¤…èj7lõl})i}HªŒJTR€H9…€àBäq[(RYSLv\c4…ØŠc6#ó«ŒK02Ú3Ú›El£cEI.Ş˜¦­)'Öšçœ`t­TM1¶x¤/êEàgŸÂšÙ?ÃúV±J’'4yß­&Ö¨ÔÑD¥Nİ$´}h£šÑD¯dÁ‰äûSœgw´¯œñ”ÃÓüjÔKTÅŞ¨'M3ø¿Â—óÿ U(–©yy'šk+cåJzÒcØş5¬S)R`N;~T…Ò½©JÜıkEXÒCw0àÓz¥=ÒQZÅ*CëMp[ó§”$ñŠiu­¢µ+Ù‘‘ƒŠayÇéR7áøR`‚µÊT˜İÄ#y9§í#¢Ò0p+x– 2‚{šltüé¥XòMZZš*`_œÎšY”©&’¶Åªwœu8¤ùA­8€zÑT•Ë!¥H·4ÂÀq}*GV¨Ù}¹­"£)***""\r" R"***(Ü§ïi`ü¿Ê—czÑåæµJÅû194Â¬{Š“aìi½+x”©à  Ó©6ûšÑ3EMŒ'4S™O^?
mY¢¦ÃÒ‘²–ƒ»šm²¹ñÏJFRİ)Ì¤ri+E¸{1£)Û9¤bIéŠy õÖRNEh·-@ÉÎ8éM©@<M(IÈÅjš)@nO­—aõ˜Çî‹PĞS	ÍIM(O¥Re()***""\r" R"***(éÍ!rOËÍ8£Rc±Z%r”F•8Ëiµ%#(Ç©#XÅèh¥Ú})0GQZ$h¡Ø(¢Š´™q€×#89¦Ô›uı)0=i¡§"!`Û¸ZN‡‘úT­÷©0=+x‚‚#ÇlSJdç5!C1MéZ¦‹äC¨Í.òGOäg›PùrNM#·¥;a¤*qÈ­§-ˆé	#*FPF Ò¤šÑ;–£¡6F1INqÇ›ƒèkD5 ¤fÚqŠ\CK°Ãñ­b5"A9T…@8 SY	9«)Bãp3œSKsÊñR9äÓJöÇz¨¶5LŒœœÑOÀô¤}kH” 6‚ê)şX=3Hc#§ëZÅ”¢1€ÛÒ™RùgÚÇ’kR‰ı ö¤qÂşB¶LÑ"9;Sj@»)|¯aZ&W)ê?Jk/<
œÆq“ŠaBO¬dZ…Èqê(êx/—ô¤*Æh™j™qL%‰ÇaéR”$ç4Y1T¤j C’{
P=I³ıŸÒ”G´r?*ÕI%Ø‡h#¥4©3G»±Ò‡8¢•¢®4(
P è)Á äÓ€ôÔ ˆ°:àR)æ,ö4‚<u«æ: †àzRa};aõ§<|ö§ÌtÃB<
M¸ê:Ô¥=3HW¹_Ò©;1Hb”‡©©A<C.N=é§©¼u#¢°g“Iåæ´LŞ	‰@8©[yë@OöJ«1³F)Tr)åp¸£aÇ^j[: 7 t`zS‚òi
Ò¤è‰€qÅ* s‘OØXò?:rÆGJ})***""\r" R"***(âĞÍ£Ò u_Ò¥òOu•)ŒÇëG1Ñ…ÏAO
<GhòzÊcx¤6š'(‡#"”CßùÓæV:c¡ §¢ğxëO“ØS–"OÒÑÑ)***""\r" R"***(H‚zÓ¶ç¢ş•&ÏöJ_/ü)s1#Qó`ÎŸ€:
6çü)Â3Ôô¦™Ñ˜‚ŒJ—Ÿ»NöÇæ)ÜÚ;‘€;
yQ”ï/”ò€u©3xÌx?wô£gû?¥Oè(ÀôwgLHÕF9¸éRã—ÊöÓ:`E@$t§ù^Æœ"ã ª¹Ó
[¥8Œ”"š\¸¡3xŞäxíŠU6§àg8£9ÅW1ÑÃ t`uÅ']ŒzSLé€”ä ç"•c`y¥8D{M;Åˆ\
B¼d
”!^€Ñ·©3xHj G"é@^qŠpB46o!3JªAæŒ”å^æ—37‹Ó­Ié@]Ş”å\uÅRw:!+¾s€3Ldbq*Á_Uı)
ğkNnÇTdWÙ´äJ,¹ÅJÑŞÔYÎ{S:c" 	â”GÎI©Yû½hòÈûÂšÜèŒìF«¸§‚¤hñÛò¾WâªúP’d9àv¤XTÍA>•q:!$0(
0=H#9ÈäPÑµGLZhf è(àõğ£H©ÇLÕ#h»14Œ½I´áı(*{¯éZ$˜½60ãŞ”)#¥JËÆ1I³åÆ9ª6ƒcpAMqÇ¥	ò¤ÙÏ4p‘\œSğ=<DGcNX½¿:¤ìtE¡Š»»Ò àRùDzPP÷Zµ#u"*z}Úp=‡â(òÏµRÜÖ2BS|²~íHJP?ÈªNÆñˆÀÀ¥Î*M¹ä¯éG’y=j”®tFddzÓZ<ô©™ê(Àì+NdoÀÆ.Ü Àb¤Ú?»úRªdqŠ9ã")***""\r" R"***(ƒ=i
‘È©ŒdzRylzSRGL$7Ò•T”ñ^?:_(j®dtA¢2
š–'ô©<¿\P##¦)İÁ€v•üiØ”áy#šMÚ©4m
ˆŒ)¿
u;Ëlğ>´àœ}ßÒîtFB*‘×ğ¡=)***""\r" R"***(<GëúR´l?®)¦m	´ÈŠ`ğh(G"¤1Ò'•ıj®Î¨TD`òâœc¥?ÊöçéJ±°<Ši
C0qœS“=ÇéOUÉÁœ·QùS¹¬j–#µ!99"¥ò¸änÂ:
¤tB Ñƒü¥g\˜¥
M^ÇT&! õ p)vZP0(:cSAÔbœ:FÜöÍ*¡cÇëV­cxÔ¹êlÇ“ŸÖ˜\çµ!f#­4»Šÿ /ãşgU!YÎ0sùÓœu¤v4ÃëŠÑE*W)3wÅ5—ç½0îşZÆ	Q±0“Ä?:F—#ü*-Ä}áMg=³Z(”¨y‘ÎxİÇüšBİÍ4°=ÍkŠT.?q¤2œÓ3şÑ¥UR3ŠÑE£aŞgùÍo·ëL(sÀ¤ªäEªW%óµ1¤œş4››Ö˜û›œšµÇìE2Òo>‚˜rÊ?ZBÄsŸÂµŒQD`Æi¯&Gn´Âå†1LgŒâ´TÍ#DÉÇçĞTA¯ëFò+UZ¤É±áLiqHXôÆSü+Ú­GBÕó	î(ûŠ‹OÆŒŸJÖ1Eª*Ä†nx4yÇŞ¢8ÿ &”cÖŠ%*^Cò=iúšnsü8 œVŠ%*"äôÖéHÒc ¦™xè+Eö(PJŸ…#J~èÓ<Æ=¨ÉÆNMR‰Jn”o`}i?Â)…›=kEh©yéG˜{ö¨·SHÎÃ¡ıjÔF©Ø‘¤QÉ4Æ•sÅFI=M¢‰ª§rPäŒŠFSQäôRkXÄ¥LRrzP	)***""\r" R"***(&í½é2=Ej‘J›'ÖšìE:˜ÊÇ­kR¦Ö“ß4İÆœPcÍ4©‘úÖ‰"ÔwäûR1=‡çK1Mp ÿ ëÖª%Æš!Î¥)***""\r" R"***(€Ó4„şui¡aìøëL9<“CdpFx¤%»
Ö(Ò0° â”ŒÔgp=iKàµjµ/Ù¶+68ÂÀsŸÊ—põüé>_jÕ-)***""\r" R"***(cI	¼zQæJMéFÖô­FŠ \1IEZ ~'ó¢ç
¨—ìĞŒÃ4ÜŸîÒ°aÉÜŸCZØ\‚şR{Î€*(;ˆøÏNÔÚsõéÚ›UcHÓl)ŒiôÒ¤­"¹ÑFH4U¨”©°¦±NüÓºÒl_J´?f0ã°Å#Š¯ÊBŠc!Ç"´H¥3yô¤b[ƒRmc›Ò´HÖ1€Í;búP‚–¬«1®Øâ˜wtQOuİùSpGZ¤W)Îy¢œÊÅ²*¨‘Íj™J)6©äŠs!$œ~´›qëùÖ‹bÔ qHAÈ´UBÃ i­÷O÷RNiŒ	
Ö,ÑDgĞQ×Š]éK³Ş­H¥7P›R2qÈ¦²gîÖ´RCh£Ë>‡ó ‚§ıkH»•ÊÄ*QFÅô£'ĞÒç€*Ó°r1¬ 8¤ ´íŒO4laV¤Zˆİ‹éFÅô¥¥
Ägi•Ê7AÀ£h=E;aÁ'ŠB@ïT¤5¬ âš@#ß0À?­7czVªCQcB¨9‘À8ïOeÂçÓHİíZÅ²”HÀ ä
ZR„tæœ±fµR4ŒF’HÅ7júT‡?…7czV‘’6QĞ†)***""\r" R"***(4¨'8©HÈÁ¦9ùGjW)!»Ò˜G$`õõ©v63úSvàô­Sv.(hÙ»MÉô©6/¥ñŠÚ&ª(f1I±})â>zÓŒXşÖ´½‘¬Uˆ¶/¥(\O	Àò˜ Í$Ú5Š¹)***""\r" R"***(&Ñ»51M¼æ›µ}*”ÍàˆÂ¨9”€zŠs'÷EúÓæ»: ˆœ x¤##¤eÁÉÓY2r+U#¢))***""\r" R"***( /AF9Í(ChØÂŸ6¦ğ,r)v(9Å< “JTÏ5WgL 9í‹éNGE !Ï"®èèŠ²±}(Ø¾•!QƒMsÈ©æf±µ}(Ø¾•&Åô¤(1òŠjGLƒ0Oš“búRªÃµ.Öô§})***""\r" R"***(”F	Á¥U ô§*waJsÀ©¾†ñĞk&HÀ¥1ó
q84õ ¯#ô©:"F{Š6¯¥H FÕ=¨M˜R… ¥éJª9§sªiAÜQµG8§ílóüèe d
®mˆŒØ¾”  0»XóJ‚3BfÑ»‚W «=©ŞY bªö7Š´‚•¶‚œûÂ”(ã­4Ú:!r&Œ‘B¨Ç"¥ HPcV¤uAÜ` t´»3ßÒ•TÈæÎ¨¡B©)¹OJJ`CŞ©3X €)¬pvÖœ=)Dg9"­ltÂö#ÚGQNÚ¾•'–1œ~´yîâÆ SÂĞRˆÆrëNT9ù…3X±y§ AK³o u§*xQs¢,3ĞSvíã'Z
àò*”–£
JUA˜sO
OAN1È¡HŞ	¢=£Å9 'íNØ¾”Š¤1â¨êˆ ĞTTr7kÔğ	éMntGa3ÔÊ™Ó9Ç¥DPŠ¤îo&& à
qFÏÉ5FñcBĞS™FĞiJ=(
s†vªº:"Ä@r)NË¥( t¦2y"‹Üè„ˆÊöaIµqŒT…rwv£bã¥Zg\;ŒE €0"Ÿ³wj6©äµW:`Èü°†€ è*^”yYçjFêCU:îJk*]éHA´LÚi‘2†¦… ô¥e$
n3Æ*®tF¥Æ•§üiáCJ©ƒÈâ©3xÌnÒ S”ê)I
0E!CüëM˜1ƒM8ÏÊ)ì¹æ‘PcæQÜèOA½úP)***""\r" R"***(?
29¦”çåUÜÚ,CÍ8m<b•Tc‘NXûO˜ÙHAOÀPH¤@SÕCšiÜŞ.ãNr?o—Ÿ˜
‚)***""\r" R"***(àf©6tFV"*	É Ó¥<€Ãp^ig=1V™Ñ‰Ö(8'8£aÍ;*ƒÔS˜ŒàŠM¬:R…úSI¦o	vÛAàqíNP¤g¾^ëOUãæGLet4  ¢Ÿ±}(ÀÆ1ÅRÜÕH`]Æ”)î´à r(8ì)›Fl@00(Ï¯&À†‚ ö¦™¼*22 ó}h
:‘Ï­=Pgßµ8ÇÜŠ¤ÎˆÎÃ
ñ“ÓÚ#væ¤U8àS•~aNçDj4F«ê´ ĞT…AãÁè)›F Ìb˜FNZ˜ÇÔÒ„æ­3hÔ" ‚2)PäŠ~ÒÃ§¢2£ S:aPn¥&Áœš~Â¿¥(CŞ­ltÆ À è)è¤‘ô !?ÃO ”îtFg¡´ ñI½}j6b)***""\r" R"***(4¹>µşfró‚¨yùß­#IÇ ~5!8õªP/Ø/!$tİÇ8$ŠG#Íh ?`Û»R@àQ‘ïùS[“À5¢J„.~”oû_¥…”Z(–¨¡Êç<)wú
m#6ŞÕqˆ½—aşgµ0º÷4Òçµ4’{“Z(ìIr=i¬àqMÃwZJÚ0±CKàñMf8äÒç €G5ƒœóZÆ(q¢8¸ìi¥ò1ŠJ+^UcEI$t¤^(qÔ™ò)Æ#T¥ò8¦—'§6GŞı)3šÖ0)R{P³Ö“€2M1ˆ$Õªe*i.3Í×Ö˜z]ç­yT…/Ô	6ƒÀªQ4Tn$LæŠMÀôæµI©ÙŞŞ´ŒÄy¦’ùà~”ŒXsùU¨¡û1K€SL™à·éH@=Iü©¬¿İÏåZ(Ø¥M.Ni¬Ù"ŒCMdÉæ­%r¹o_ZPAéLeÁàãi)***""\r" R"***(A"‚À:fâyÜ(9ê}ê’4TÅó=¨ó?Ùıi±=1K°w5¢Er½}JBüŠ6ZB‡µHjÆ#¼ıi­'biÅ fšÊHéZD¥I)***""\r" R"***(ó=©äc#šLæµHÑRH)ÈÀu¦ÑV‘^Í-ÇÊ;S	'’hf'ò¦¸ç¡éZ¤Z§tø~t„ç¨çÖ“ÔNZF±¦QÒŠÕ#U¢îşKô«H¥
Œp)¥H"”³v±=jÒe¨	Ev¤`HÀ­)SÄ“ŠJ
·LU\A­…„ cŠqE´>IÈIa-ØS[9ç­8°M5ˆ'ŠÒÃPw‘·cå¥Á=¨Áô5I©ŒÚÇµ%Iƒèi¡­QJA ?h â™ƒéZ¥qò& p3LflàşTò21MØ=MRVf[€ZiÎy§2`qšiÜU#HÀ(¢Š²ùIæŠ ' £ĞÕ­‡a÷*¨#$SˆÏP+E±\¤g©¨Û©úÔ¤)¡@9­ÃQwµjp t´ OAT‹Qà“;SsÎjg\J‹Ò­\ÑAØŞ”@ä~4ı­éC.G9¦®>WĞŒ€zÒm\ãıƒÔÒ2ckDõFà‚ŒŒyBİA¤d#ÿ ¯[E¤ZˆÍ‹éM(wp8§íoÊ§ĞÕó*w³È§æ—ĞÑO™Éa6/¥Ò–ŒJ¨É(…TÅFT’*R¤”İƒÔÕ¦56Q´íÒloJ” ŒÒ$àƒZÆEr‘G&€zÔÌ˜S3×ùÖ±‘J$b0z
zÆ«B§š^{ñUvZˆŒœğ)v"Ai
‚rkX³E”;ºqõ§×õ§ìÖÂœVªLµ6 ği6/¥I°y¦+H¶ÊQ" ´å ƒR„fƒÖ·‹+”‹czQ´…Éâ¤Ø{Ò” qšÓ™šE“Å)\($sRm8Í!Bx Ó¹¼Q õ¤*ÁíOdÇLÒ#üiİˆİ«ØRQF¡¥(ÂÍâ¬ÈÜ qÔİ«éR‘ØÒmÅ4Îˆ¢=«é@ŒÀıj@ ¢”&:Z¦t@‹bç¥<"àqKåóœqS€E;êtGQ ĞQµ})ê„‚H¤Ú}*“7ŠÊ $
E œ{!Æ)***""\r" R"***(
£…¦Ù¼P@è(Ø¹Î)ì€t FzµMÍâØˆ õíNØ½@¥DÅ;`õ4ï¡¼Du `
@¼p*LgŠUŒÍ;¤tEˆşl‘øÓ‚ôâ‡8¡zMˆÍ‹éMØ}*M‡<p‹†¦úE2=‹éOvb—Êàpiê…³iÜê‚TcLd;NáÅM°zš
 8Í4ìt"5EÛÒ•T€)á9§,xè(LÚ#
‘ÔRSÙsÁ¥Á¥]õ7âSÁmÀ¥Á=.ÓŒÑvu@nÅô£júS¶¶zRG´LŞ;‰µqŒPqÈ¥Á8À¥Úq)İPcv¯¥ ĞSÂsš6SV™ªvFGE§l_Jz¦zşy«R:"ÄE àSö/¥*ÇƒĞÓ¶SM3hì1T ¥1ÕiÁB‘Šs.G9£¡¬XÒœ)***""\r" R"***(¢…Oï
p £)***""\r" R"***(éNìŞM«éAPNH§”ÇCBÆHÉšgLÕ\”S‚r)Á
ğ§,yêÓ#)qŸjQ?ÃúÔ¾Y#n)***""\r" R"***(2@4îÍc"1Çğ è)LE€$ÓÄMÜSLèŒ†RäŠ‘“'œĞ#ÛÎãZ]Å±Š‹¸qOØ¾”mİKI»³¢R åÕSEMå†=è1c±«:"ÈÄ`ò¢°úTŠ¹ëC!€i'©¼Y C1Å<‚84$Ö‰¦uBD~”Söq·”)4îÎ¨=¶ƒÔRãTª¹<Š
‘ïô­"ÍÈ†;ŠFºÔ¦.Â‚„œàÖ©ØÙ=H
qÛÖÇ‚N?°T«úS
ØÅRw7Œ†R3Š?º*O-±šBëùU&¬uFJÃy ĞRá»ƒFÖì)***""\r" R"***(4ÍT€âšPg#ò©
zR$U¦ˆNÃ \àŒ­8 8'‚)U1ÁÍRi›©ÜnĞy"…Ü)***""\r" R"***(?`õ4ôO\ãW6Œˆ‚ÈjEOAßšr®~ğ§+ØĞ™Ó	’0zÕFó«H¦²îèy«LèR!*Aö¥
ıœf,“V™´$7búR„`
RŒ)PyIêtÆHhŒƒëN1ÓÓ¥<)n†”G›‘´f0(=Wõ¤)GåRìÅ@i&o²0 ãŸ­0E?Ê'·¾W 5WGDer,7qšUŒ0û¿­J# äN1É5ièk #9ó9ëOÚOAO:óG26S±Æô¥({š“Ë§tk„AyÁZ
ÿ ²G½Kåc“G–LÕ&m¬ˆ y¥ ‚¤+ÆúPtîÍãUŒÀ¦”î?*˜F@#šS:SLŞ"ÚØÎ9ô§*ÉÔ‚<ôÍW±­ĞéŒÈÊƒÉ¡{Ry|cSœfÑ›#	è)è¸ê9§ˆ™¹á}i¶tÂgd]HàT~`ô4ŒXI¦±ãıküÚP?ç™Q$Ş=)***""\r" R"***('˜;
ˆ9?Â®4îÈ{7ÈSK)ê)***""\r" R"***(FÒ1Í b;ÖŠ™j‰.äşïéFõZyôÖf=1T Ä‘œ1ÎGçM,½Æj2Ì½@¤.z“T©P$2 p!`Nr*"Xò£v:ŠÕ@¥D“+ê)AÇ`j-ãĞÑæûšÑ@^Å“ùœÂ£2ıÓM.?½úÓ7“ĞV±¦5E²BÜt•0¸#Sûş´Ìæ­S-Q$.1)7àÓ8•5Ÿ#¸5¢j‰!Ô	yè)***""\r" R"***(C’zÑÈèkHÓ)Pò'2¯^”ÂÀœäS7d|ß¥4¶;Õ@¥BäŒÀvÍ&äşïéLŞ=)***""\r" R"***(Ç¡«Q)PdÇ§ãL.3LfÏ|}M'ÌyªQ)Qd›Ç¡£z¾êÛqÖ”1Çj¾RÕå”ŒmíéHH4İçĞR$`ÕòÙæCC0#¦“ŠipG«ŠFã‰ÀÍ4¿ ¦–õ4…”w­TCØê)çø:c6zf1qŠ)QN{S]T·#ñ4o>‚±=êÔR)S6ãœPXÆ˜)***""\r" R"***(“NÈÖ4“¼z7CP{nüh@ÅZ‰^Åî¢¸ì* äúP\tÁ­TAR°âã¡Å4¸ÇJnsÍµ¢jŸp'<`Rƒµ€ïLcÎpkDŠTî+= ã°¨Ë“B³væ­+CÎP)´ûÒ±ìß¥6µHÕS°˜”àê:ÒS[®@&´HµLyqÔøÒuæš#æü©À`b´JÆŠUb)wJm(SÉ«Hµ=9¦FiäqÍ5ùBãğ­"5Lnïc@—)¦ì¦­&>D.G¨£ƒŞ“`õ4à éVùSÔÖ$|¡iÔŒO@*’hjmÓ¥7wû#ò§œãŠaÜNHı+Dh Èì(Ş}&¡£ĞÓ²+‘¼ú
LCF¡§p1·ô¦„à ä©¤n‡œK´ÃĞâ­6%œ÷¢ƒÔÒÎJÑ\ÓRp3Mf&”äGåHßîÕ$5)T)êi '¥*®zæ¬¾Aßw &“{zR“ÄÓ’yâ´€“š(¢šmìÂ›°I4ê+DÁ@nÅ÷¥Çjx@Fy¥ÿ ^©2ÔlF@§jeK Çµ0 Š«Üµ ı(ÁE#çzÕ¢¹`€õü©¼gŠ\7¡¤Áô5I¤W(P@=hÁô4ª¹ëš¥ å#e àR`ú•€’­6RÆªdsG””ê*“±j$eTbŠ\İ)ŸOÒ´M¢˜Sv©ö§í$?:CÕ¬KPÈ Í6œOPÃò¦œgŠÒ,\¬ ò3AÁ=(¢´EÆ(nÅ'9¥Ø)pŞ‡ò£ĞÖ‰•Ë ›°zšxR{RV«a¤1†)¦=Ç<ş!@Ni@ÀÅ_5‘iÂœıßÒ§*)***""\r" R"***(&Áêjã2­b0ƒ¡@§ì¦‚€ó]’HfÕÎqHÊ:Ó°})OÆ©3H¤'–=M1riÔw7KR"ŠñŞƒ4­ÔÑ‚z
µ±Ó $jzŠ5Î)ê¥zĞS<‘KšÌÖ(…“§,jFH©yéÅ
€Çµh¤o†,j½©J)§ùc¶iL|ci§ÌtD‹`õ4»¤Z
ƒíG9´P›yÅ5ãPx©0})***""\r" R"***(#('“V¤t@ˆÆ1Å0?úÕ(P?úô…4ùˆ¿Ö‚ëRlZk Œš9˜¡U6Ş„=;S°})***""\r" R"***(ÍÄ^ÂŠqOJAæŸ1Ñ Tf€óJ=P’i9ÔEHÎ)vSNŒJ.’()â5©UF3Š\CLÒ7Lã\ğ)»©©¶’GçHPi³¢2"òÇ©§tà
R§8ù°j‘Óq¥9¡“=A§ì¦—4ï©Ñ¢ƒš_,zÒªíïJAERgD°zšFAœbóg¶(ØIİÍZiÇqcñ@A¦œCz6œd
³¢nÁêiv-(ÀëNÍ]Õã¸¡@§˜Ôr(Ø=i[¡úS: ´}¨ ñER5ˆS‡ÍòÔÜÂœ€ƒÈ¡»3XŠ)âœª­!SœàşTäg"•ÙĞ¶hÆ1Jª£Ò•T“O˜Ö,]ƒÔÓ‘ =M c¿çJsU{›Å‹åSJ
Z*™¼GĞŒâœ‘©Îi úSĞœŠW5[)***""\r" R"***(’!ØS
ãƒS†£cÂ©HŞ2±ÏöJPƒ¦9§ ä~Tı™õ\Æñ™Üv¢¥ØIÁ4 GçUtÍã!TôÍ)PhUÛŞ–©ntBCJ¡8<RÅ+[42œæ¬ê‹¸Ğ·4ƒŠp@G9¥Ø1Ö­XŞ2°Í)P@µ(àbŠÑlnÄ
jBŠ9Í;ĞĞÙ çÒ´‰¼XÂª(c‚(¥Pwt¦od
8¦•SÚı?mZØÚ-Ø(Øzqu`úgD¬Š ¦•SÚ¤)¸Ñå{féèEåZUŒÄÔ› 9¥UãT¤k2,sĞR÷§:´ã“ZEÀ*‘ià~í B½§«Ôb¨èŒ†²€r7hÎqRÓY@çÓ±¼f3hô•8Í­!¸§s¢2¢»B <J˜Ï|Ó©¦mj4F äSÂ«ŒH{SÂ•éÏÖ­;›ÆCYUN1ÅA=	¸rA ËĞqToØ®?
RŠisEÑ˜ ¥;Š\CNUÎ)¦mŠ¨3ÁüèdÇU§…œP¢©;šF©ÁœÒ€¹ç&9¤Ú;MnkƒY@˜\p9§…´l­Æla¢œ"—n:~F•W)›Â¥ÄÀì5‘G¥HàñùĞH«[™
8 Ó€^Ø§4}ñšO+ŒÓ6F7
[)  ıßÒ´£ó§„\
w±¼jØjØ~TõèFÑéNUÖ“™¼kk2‘Óñ¦îZFe#¯ó©A#ü
ö"– u¤.ã4Òp:ÓYÆ8&­D=ˆâqÉ¦ùƒ°¦œ‘‚iSúÕò‡±æ{R'¯İÊ;ÓY³ĞÕ(2•äúšBËÓ­FÍ·µ4±5¬i”©ïôÆ÷‡Ò£mäğM0õæ´TÒ-RDŞhşğ£¿éPŒwÏFªQ²ò&Ş;ŠF“•ãê:MÄ÷­T¨¤?x£xô4ÃŒri„œğÆ­Aì‰YÁf›Qä÷4«·?5R…†©È=)***""\r" R"***(¡¦îQ÷E
Ê;b­GCEG¸æp?úÕ±=)***""\r" R"***(+yÖ8ã­j¢W±¾:š€ñškuÈ_Öš[Î«•°dŒê:ş´Ó0úS7Ş›–şïëT¢Z£Ü“q?Ä?3î)***""\r" R"***(G–şïëKZrØ¡ä€8"š\âœšk2‘ŒÕ$?cqÅøûß­!qŒL¢´H!K1IEH¯bÔÑ‘ØÑEh½dzŠBàZF`8ÅZM‡²lƒ=?:ŒÓ3À¤ÜSúSäÔ¥E¡æCØSF;ŠMëëI¿Ú®)–©¤?w°¤$õÍ1ƒ¢‚ÿ :Ú)©Ü]ã›½…%kBÕ+
N{
kğ:ÒÑWªHŒ)D˜¥p2qLÇùÍZCT‡1ù Ïz1ÆqJpëWÕ;)***""\r" R"***($t&”cµ`â€	8ªEò…{QZ¤‹PBîİo$v¤£i<úS¦†³cŠiç­=º¥3ÚµV/”(ÈM.Æô¤d8ù…P(	‘ê(Èõl_J6/¥RÜ~Ì\ƒĞÒ1â€ è(*­XÕ;¦³qO(E0®âNj’W*ÌMçĞQ¼ú
_/ŞšF)Ù˜»Ï ¥ó=©´}h²VÇo”ÃĞı)ÃŸ­#`ğ*â\i‘ÑKåz5(AMkÜÒ0Ü1š íIåûÖ‹a¨X`ÂŠ2=iásK±}*“ErŒæšS'$Ô ĞS_¯áTËQ"#SÊƒÏz@ƒ<šcåøQOØ¾”l_J¤ÃÙ@Å>“búRÓNãä°Ö\òM7Õ!b˜S9­Å()***""\r" R"***(##¤«ÖHÃ8õjÅrê#íÇ¦Ó¼¿z<¿z¡ò z
x@:Ğ M;2”.FèsÉ¤òıêR õl_Jµ"½˜À ğ@ãğª@¤)“œÖ‘Ôj#òıé¸o_Ò¦òıèòıÿ J¥u¹J$ MeœUƒšcÊ´Œ®_)Œgô¤	ÏZ ÏQåûÕ¦î6Â¸€›OZ(÷¥­S±6ddÔÒsØ~u#.îô AZ¦RˆÌmàŠBíR2î9Í'—ïZ/"”ü¿z`ç5'—ïJwª»+#ÀôÃÁ5!àš+H²¹Hè œœÒ…' ­“)DJB€œÓ¶7¥)Læ¯˜Õ@ŒÆ	ÎiJŒ`qN
M/—şÕ>do‘2 ?úÔ*çŠ—Ë÷¤eÛŞ«™›Äh@:óC.êpBzñKåûÑsh¢&P=iD|zT_½1úÖªF©HÆzÒAÆiÁ0sšB¬Iâõ:!æ4(ÎMAéÅ<'­^OZ¹´D•É¦lız±åÿ µúSYqÆ{SLè‚!+…?áHøÔ¾_½_½>c¢*Ä~_½?z˜EÇJ6gŒt¡HŞ#§ÇcOUÉÇJ_/Ş‹³¦(`@)***""\r" R"***(&ÁëR¬|~4_½%#x¤Gåç½=cÈ4â€®@üiËjÓĞÚ#`õı*@œuı)V<ŸZx¸¢èŞ$[=jE]ÔªƒÔ…03šfÉ˜Æ:Óvîş•&ÒGJB0W27Š"(	ëAŒgŠ—júRy|ä¥#¢Ë÷ &<Ô…éI±½*¯vo3ËäÓÙ ÷¥	´¥7£x¦5cR3ùQ·)***""\r" R"***(·úT‹¥Np(:"3Ë÷£Ë_J!îivŒæ­6tE‘ ôı)Á8ëNd$sNğ9­§DXŠ»»ÒcÖ«3Ö†Ò´LÚ,‰ø£Ë÷ı*U#šFŒgúS6‹lEŒ4¾_½9àzzÓ¼¿z5‹hòÇsNUÏíOUÇCš‹êmcb¨SR„év/LU¦l¤¬B«sO'm?fÖş”à™Í;³HHh!AœÔ›1NÓîoEÈÆqR OAJ#9§"Òô7ŒÆ6ji@OT¯=i¥jfÉÜb §„ÁÎia°iôÑ¬F2ãœÒQO`Hâ˜' UŒÿ U)Œÿ …*w¥#¯Òª-1#*ÆåM*T`=j_/ŞƒıjÓ7Œ¬DŸ§­!ùx5)R)¬20kXÕ3FAş‚”9"”&FsVâÇS$ëŒTŠ»»Ò²Ò©=NˆÊÄ˜9úP3˜Tô£`ÎJ¾cxJã0QH9©xù‡JZjGDZ°À¡)***""\r" R"***(8 yü)@'¥;Ë÷§{£X±
…8•%*®áœÑs¡KB"€ŒÖ…8)8¥	‘œÓÕÆD;O/Ş§xøëLØ1ZFFğv)B‚:Òìy~õªfêB'ŠNğ‹œbœb
)***""\r" R"***(Q¬fFª„ôæ•”špU÷ €x4FdxQÈşT*î5(ˆuœPbƒ¢#UÛŞ””ï/Ş•Woz¤tBCUAšäTŠ»†sC)ö«»4SÔŒ 8ù©Áp:f”&Nà¿.9Áâ‹³xÌA¥<”›3ŞœªLÕLr s‘N=)ORGZ¥cHÈ`Á<ÊœœÒñ´ dâ‹³HÉÚ;cò£h#œ~Tı˜ç­&2p?*¤Íã+Éæ— t{båûş•Wfñb•t¦°ÁÅHAE4¨4Ó¹¼d3¿Š23ƒÅ<¼šB›Iª»:#1¤Ú:

•ëN:š¤Ù²˜Úz'§4å\½)è„t¡£hLÔf$ñÏÖš[°4ŒÇ’qLgx¿Ïf…~ÀysëMŞ¸ÇZŒÉØ“MÜÇ©­1{gLñI½}iœôu«öcöœu9¤b¤p¿0:Pî@É«Œ¨ˆÍƒÒšÒ.y­Ã­FÜô?¥h¡rÕ!ûâô¤Ş¹àÓÖŒZÑS±¼Re=)***""\r" R"***(3põ¥ïO”=“Cƒ(<´„óM4Òã¦9¦{!ä İÀ¼šiv#RU¨–¨’&ºö¨ÎqÁ4³t&´QE*6&	çŠÜTä8Ï©EìÑ.àG'ğ¦¶3òÓ	'¾>´ß­ZJÅF˜ölwçÒšH=sùÒgŠ*Ôt+{
9ô5³ê:Ór=j¹©&J¤ •¢È=)***""\r" R"***(Qˆ{$‡³Œi…»“A94­j¢†©	¸€iWù¿1¶çŠnî~éü«EÄŸ÷t~î İşÉü©AïÒ«~É~îšåAàÓ2}¿*B}qMD=’\zf“+ıßÖ“#ÔSpIÙ²Q³?Î˜Ì M}èlzÖ‘E{	9â€	íù(­,‡ìÒ´uÛN=9Ô g&‘È'­4»ìÒS°£+ıßÖ’‘†F*”[(¬W1MfSï@@:Ó°=h£b•43+ıßÖœ„ƒŒ£¶7è*Ò¹\ˆ“Œ{Ò©¦ƒº)	'­j¢¬>KŠÄiUğ1ŠmJ!ìÅ#¿éIE¡|š
FiÇ89¦QEZHJ’½…!8äĞNi¬àŒV‰(!w¯­#2‘ŒÓi	ÀÍR‰\ˆZ)»Ç¡¡Ÿûµi+‹“QÔƒÀŒúô0QÁÍZH¥L=éÇŸÂ’ŠvÔ=BGJ(ÆZ¤ŠTÆ0ëŞŒ¯÷ZV
S@dÇOÒ¨µ
wò21MÜ½‡éHX“œĞRˆl>¢‡ÔRdúš2}h[‡"çš*Œâ‘Ü)äÔVƒä¿­/™íúÒ•›±½EZz•!X¡ç4ÒiH â“ğ«I)***""\r" R"***($5“šM‡ÔSèª/”iŒõ=é6QS(ùpE‚€äd^[Ty4ìĞQ‚z
wŒ‡˜ËELÀÒ£*qÈ?•Re(‘ÑO`1À¦…$ô­">Q¬	İ‡ÔT¡=M(Uª®ÊQˆyæ´(ç­; tÖRNE4İÊQÔm4®[5&ÃÜÒ0 àU£¨İ‹éMm£O¤(¤äÖ‘‘\—E;ËZP£*ÓL9İ¦šÊ¼*Fè~•àÖ‰Üj$L¤œŠM‡ÔSÂ·¡¥
IéV¤ÇÊ4 Ç"‹éNeÀÍ%j˜r(;Q°Ó©|°zb®2(UA9Å5¶÷ëŠq]¾”ÖRNkDîRˆI„`âƒ•=hqŠÑY£p¦”$çŠ“fG­&Ãê+E"¹l3aîiÆ9ş´»Úy«R‘Àh1©5&Îx<PSÒ¯˜ÚTc R*`äÓÊ3@R{SægDPÖŒ
nÃê*M‡ÔS‚M3E‹ Å;gy§QŒôJF±Z‘²ò)
p*FRÆ€xÇçV¤oD±úšV@zSöe¸éíJcÇ\Óæ6ŒHŠzS•qĞTàB®z`Sç7Š°úŠ
0âŸ‚z
#¨ªº: †$dQåŸZ/€¤”¯©Ñ¬7Ës@< )åNÜPªAÍUÑ¬D`äb” ïO ŸZ–éS}MãpòF1i¯-5”“š£x»‘”ã­9ıÚvÎ:óH£ƒVÍâYõ£Ë>´ú)§c¢(j ‘OU’zR`Ôà
©®èèŠB	ÂĞPš  ô?•9¹¦m† IÅ.ÃÆqJ¨AÍ8õú›­ÈÙ8æ…Œ‚ü)½R7ƒEŠqŒŒRÒ¿_Âšlè€Í‡4ygµ:Œ¸­§Dl3aõ¥8âF\U#Xî4'­9ëÅ:ÈªLÖ;†İÃ? g½9T€Aï@BjÓ¹Ñ ›¨£aõ&	¤¦m¡9ù¨(sÚœN)Ê›O Pj†,yàzTª”¢>21NU+ÖƒX´ Ò–°úŠ6QNìÙ‘‘JªAÎiT0iÀdâšlÑ)***""\r" R"***(dÏJP01NòÏ­=MQ¢º#)ãéV%Ç"HŠ4ŒˆÙqÁ¦”Éã§z”ã#4Ò3ÈıkDtÆC
ñJc‘KJ«M>¦Ñdevœ‘‘FÂy#Çšj©SÉ«7‹ ‹E+ Î)***""\r" R"***(çã¨è„˜Ãê)***""\r" R"***(Ò–šÙ)***""\r" R"***(‘T£!JqLeÏåÄĞS<Š¸³¢De8â„R£¤ÙÇ½&ÆìE_3:"Ø‘ŸJCÂª@ ÷¤AÍYÑÆã<Rùxà~¥IšÅö ´l_JZ)ìo1
Ô¥AëE'sxI84R…-Ò”!µZvGDd6œªsš
ƒÈ¥QŠ»5LFBNA¦”\óJr	"„óšÕhm43§İ¡XÖ–šfÉ±Œ6šBàÓÙI9yÅkvmX`Q» sN1œsÍ?Ò—iÆi¦i‘§_JU\œf'†Œ¸ü)ó#xÍ¡¡=i@ ¥¥*ERfğ¨Ä NzP¤ô£c{U_ChÉŠçš]«éJªNzz¨Ç"„m;ì_Jpˆ•ïJP“špàS4RaÇ~”2ãƒEH@=hO±¼ebœ‚)Ôã=)***""\r" R"***(<Õ&kˆãíHG?Ò¤ÆOJB ğF)§shÌe(\ô"PÎ(ÀRfñ¨íŠB<ŠqRJLÂ®æ±¨ ¥Ú¤ó@9¥ ‚©3xÌnÅRéûO§å@ˆ«V7@UÈâœŠE `cõŒÓv7Bs!<m¦“œÎ›¹zBÇZşPGø™ì“Ş:Ór}M#1Ç'õ«P°°âÊFi7/÷çMÜ§¸¤fZ(!ûûÓûÇó¤f_Z‹§ZRIêj•1ª Ä·QFG­ÿ 1ğ)***""\r" R"***(Rƒ)RCò;ccµ4°­(9ÍRƒ)QAFO­Säaì|ƒ'Ö‚ÀõÅŠŒòsMA‡±òXÔşdzµ7ç4c\ˆ~ÅŠ[ÓŸ­&O÷h ‚G©D¥D2})***""\r" R"***(.Twjc¿ÅI¸úÕ¨Øù± uÍ7#ÔSIZ¨«±cË)İùRe¾i´QÊ‡ì@õ¦œgœ¥:“jÕi)***""\r" R"***(Rå	¥zş4Ü.q»ô§šÒÅ*W8õ¤.1Ò†f)¸ÿ 9«I°w’sŠ(9ìi6ã«´ŠT¹ö£>ÔÂ}ŒŸSO”^Å¡¶ú~tÌŸS@Ër9«Š¤±?J\'©¤ØŞ”loJ´ı|ƒ¡4‡Ö€¬:
·CNÁìÄÀ	ühÉô¢Švdû& ôœQHÃ#ŠÑ"•!¥›¹ü>¦‚1Æ1H:õÅZV+Ø^i»
PNß”çëM$)***""\r" R"***(\v²bOSFAèh#4«·ø«DÕ;N>é4™>†œÍ“Á¤­V+LŸCKŸQŠ(y5Bä€ ÒRá½úQ…ş÷éV‡ìØ”R…oJ6dñZ$R‚Bc=ixà
Z*ÒEò*GQM##) ŒM‹éNÃP"Ø=M(@*M‹éMpAMOÂšÀu&HT¢´Š)BÃ)FŞù¡ÔÇó¤Æ9şuiX9®:…¦·#Ÿ¥ 9îqëšqÎi–©Œ%@Î3FäşïéC!ÎE&Æô ¥8¨=©6S@W=I§ìoJ´¬.Q›©¥§loJ67¥0äŠ]éHT¢¨… OJ]éFÃäÒŒJ]éFÆô«æ ÜAJséN^iv/¥1ò€UÇJ0=(àQ@ùP˜‚— t»Xö£czU¦‡Ê4Œ”ÒŒF1RloJ62*cQ"zPÑñÈÇÒ¤¤pHàU)2ìˆv7¥Ò¤O^)ÁzÑ6>R0 vÍƒ®?*“búR2óòŠ¤Æ–¤[Ò“Ë?İ©v7¥Ò­dEåŸîŠS &Æô¤¦UˆJc€)***""\r" R"***(&Öô©6Nx§P:V‰”ˆ'÷©>x©YÔy~õ¢cQd&?QL(sÀ«&<ŒfšbÇ%Z¤Êå+•=Å Óô©ÙxùE4ÅvşµjVR,AK€:
“Êÿ gõ¥ƒÚ©I\|¤myÍ0Å­X1•êi¦2z¯ë[)ÈƒË?İ GÏ#+GŒãò¤ÙÁ¢ÒS)67¥Jª=. «RˆŒ  ÊĞ@Çİ©|¼ÿ  ÅÁùZ¸È4 ÚGQIÔâ¦òıé|ƒœš¾diˆv1íJ#P1R˜ˆ¦„lò*¹¢0'<š8ùE?czPçšwfñ°Åˆ°æ¤ñÏåIµÁãŠ“kzQÌmÜˆ¨^¢€›¹ÛR˜É9ÅÒŸ35Qdb3Ÿ»Jc§„lò)1ƒŠjF±LiL–š## ©v·¥(Œš¾c¢(‰cõúPÑóÀÍOå³úĞb8ª”¢š!6àÒ„ Óü¿zPŠOO™åîÊ“ËÛÉ6Æô¤t8æš‘ÑèBàœbœ©ıÚzÅ“ëOTşğªL´¬1cë~´Ğ‡<ÔØ ëHÊsÀ«[Àˆ¡Ï©Ï"Q½?Zr¨ãšw±Ñ3Í(»O	ódóíKT›7ˆÃ#¥*ÆM?kÔ¨ÎE5s¦#<Ÿ¯çJcã‘RR0%N*®l·#ŒñKåŸîÓ•H9"Š´j·#hıF)‚>x+ôüi67¥ho=jB„õZ6?¥>…cxèGåŸîŠ0:b¤ö£Ë9İ·š»›DŒG‘¢—aÆ6Ô›Ò€‡<Õ&n®CåëJ#ãîÔßgÏ4Š‡¦j®b5#àçÿ ÕH#Ö¦	Æ £ÊÇğşµHèÏ,ã¤zT¡yı ñŠ±¢h„EÇNirEN"ÁÈZ_+'‘Utk1Wœ‘NEõ€qNX ÷¢èÕHjÆH¤hğjP…)***""\r" R"***(¹äS6‹#
:có§,|ômoJr‚)***""\r" R"***(©ˆS)67¥H‘({Õ§sNaœéÂ>>í(Œ‚šI£vJkGÎ@©
ÔljĞÙHŒG“ÊÒˆÔSÊ‘ILÚ2cqHÉÆH§°Ü1K³pÆ3Š­á+‘„ÏEà™ÎêxŒ‚•“ŠgL$@ÑûSv¼jfRy”ÜãZnt&F¨AäqN##ŠqF¨òÈiójoÈÂ’p(ØŞ•(M­Z•Î˜ËB?,zš})ûÒ”§<U§©¼YZr©Ï"œÉ};Ğ2N+Ecx´!U<bšQ³À§G$P<
wÓSXŒØŞ”ª¸ê)ûÒ•WE+¤mc#ñ¤©0=)
j“6ŒÆ§ëJ@§OQJ–šgDZc|tæ“â¥ÚŞ”y@EZfÉ¤Eè)BóRy+N0°«M¦G°Svyêb Òl úŠ»³XÉ
	À•SÖœgÍ8!Ï4ùc+ÁÎ()¾¥sƒùÒydUs¢#ÚŸ±iÛÒ”!=x§sx²3>í*®"ŸåûÒ9âŸ1ª„“À§ãiU@äiÁIä
¤ÍcRÃ6ù¥Xé“RäP«·¥4ŒÛ"r1FÃ• ôâ£
ÔéŒ˜À /—Ï+@V¥>´)I¡¦%ê*7 u¦'‘¢#“T™¬j(=Ç©Á3ÑE="üië¨Å>dn¦ˆ±ğ¤ò÷rLc´^ÑòÓLÖ3dK•â±ŒñùS¶ı})UH9"Ù´fÆí0?U‘NØ	éNØİ1O™›Ædf>zND<à~táEH±àô«LŞ5
¤Œ`úw¦‚£izŒÔfVêOé_ÂªÏñµQ'lã?:iî*9<`Ğ¾qT©²•L}¨çĞ~uá×y¤.BM_³+ØDš‘¶÷şUóïI½½j”`º"B¿í
k8)***""\r" R"***(M3cƒŠkH3š¥r}‰'$d?éMÜÃÔÏ3Ú˜ÏÏÿ ^´Pl~Å²míëFæõ¨€v£Íİ4ı™>È°O«ÓN3À¨„ÌiLøôªTÊöD”„6xoÒ£7ô_Ò›æ·©ü©¨ TÑ+nQß¥!bzšŒ»÷¿
BäŒJ|ˆ¯eäIED	ìÆ—§zjöL”Œ–‡¡ÏáLÜ@ê)¥Ô÷ı*¹T™.G¿åFG¿åQo_ZPAÔì‰)±øS2OZ*”lÅ!à»¿JP»0şğ§‚CV‘Jš M*Vı)ÌFÏjeRˆr…ş÷éFf¤£Õij?f˜ZM‹éKÏ üé'ªşµ|¤ûÒ”İª1“ÿ ë 1QÖ­AÙX—ıïÒŒ/÷¿J‹Íÿ kô¥Y2=j¹,?dÙ&ûß¥!#ßò¦™aAfê)***""\r" R"***(¶d.ĞÑµ})»ÛÖœc“V¢…ì€"“Ò‘ÕFyü)K¨ÍFHìãZ$ƒÙX6/¥ÒšÅlRsV¢™jšµ})
©é‘øSi2=E5tŸAáG|şT£ ı)€‘Ò—szÕ$O³TM5±(vR}x¦3ü?+XÇ@öc¨¦«‚9?¥( ô5¢Š%‡Üñ@Àèÿ ¥% g½RCäCğßŞı)ÁAèÔĞÊ3KZ$Í*¸àS
œr(2c‚i7/­/Ù†Åô£búRäzŠMëLj6/¥#€:
k;vÍÍ´Ò)SCé’)»ÛÖ•Xœ’kE¸rËƒÀ¤ö§ï_Zc0-ÅY\ˆ)Œ¸ù³JKçŸJiV'<Ò±\‚€	äâ—g½4+zxÈ b­4ƒÙŠ±©§ø©0¿Şı)Å8AÉq6ïQåûÒ`Gú	äC|¿zæEöhM‹éFÅô¥¢–· ›Ò‹éKERL|—búQåƒÑihÜÃ¿éU¨”•FqHÀ¥äóƒùR…'µ2ÔCĞÓŠ¯LP:b–Ã”o–GSúR4co&ŸÒšÌÀ5Z—Ê†l_JFN>QN¢šÜvDx>†ŒCRQZ!rŒOZPƒ½:Šµb”F” äµÄ)***""\r" R"***(4’y4Í¸_ï~”ß,uÆ}éiÊÀT˜ÜRåîš<±ıÓRõ¢­1r‘ˆ?v†Tâ¤¦?_Â­2¢®1”cM*O’Š¤Í9„‘Á¦ù~ÿ ¥Jà‘À¦`úÑXN#Bæ—búRá½(Áô4îƒ•‰´1Î3AŸJz3‘Hı
ÑI±¨¡_½!R1O¢­=GdG†şé£ËÎÚ’ŠÓ˜N)‘… c”&zÓé3éŸÊª2.£J3Iœô&3Å'—pjùÍC
ñ‚(Xƒv§· HªAÍZ•ÍTn7ÊÀZQ)***""\r" R"***(?8£©9EXAçm8ÆIàbŸzwzjW:`ˆLdwı(HäÓß¯áINçDP›W¦(ƒÑiié÷E;³U¾JÒ¬@p:œ«¢Ÿ34I‰ä¯­O§9çwfĞDqšA$dÔ­÷M2šlİ$„Ø3ŒR2¥8ÂŒCZ#x¡‹$Ò„­<)'ŠBê*®n’$c$RóÒà“À¥LÈ­)***""\r" R"***(b’"1àõı)V<rñ§º“È¥_»T·7ˆß,/ sH"äŠ’ŒJ£h±cû¦œíO<(^”\Ş,‰ çšaŒ‹V™•R)İ›&B"9çùPS·-#FZf±³"òÿ Ú¦í ã¥
IÅ!S•I›Áˆ#üiéºĞ€ŒäS»Õ£h±­'‘J#™4´U]Å°ò±ü4ß/'5*}ÑM`wp*®Í#& ¦:Qåó÷M=PpiÛN3T™Óq@ñ¶,v¤¢ªæÑØËÇğšQ~cÖŸE	»–·åûÒùxëNO¼)ÏÓñ«5NÃœp)È¾¢EñÜP»†søS|±ıÓO½:šv4NÄb Oİ¥ĞSéé÷EÌ´ÙŒtÅ*ÇÏLR°%ºR®ìàÕ^ÆÊB„”¢ †”èiõJE©"#?†€*R21Len€U&h˜Ï/ıª?zqò(«OC¢Œ0´yXä
} dã5\Ú›Äj®zŠRªGJZÕ&Í£-HÌ#Ò‘¢ ñü©ÌÛi*¨1|}ÒhÀÆı)èOJBOz)***""\r" R"***(òÁşK³<K—¿•<r)ŞÆ‘‹i¯ŞÕ*3‘JÊ­\[:#"·—ÏZR‹Š•¢ çÆ8­ã!9ëÇÒ” =)ip})***""\r" R"***(ZzÆLhŒ÷ş¢ zÓy©Ù¦m64B´†§¥Jß1È¤Áô4ÆVåÿ µúQåÿ µúSˆç¦(ÈÎ3ÍTM£44GïHTö¹`zfœ:V©)Ü`BzñR*îi0OAO
Jw4ŒÖ™£Ê)***""\r" R"***(ÉÔ»TŒ‚i0{Š»£h²%Œnû´ò€ôâUHÊÒ`÷â„îmìÇsùRˆÂã9ééN Š\Ó5Œš =ƒ¸§)=¿)X3sÒ­Æc6/¥!‹wNŸJw#ƒšrÓ4XÑHjÄ:~´»
ğ)àdâ”¡¹¬h¦4*‘È Eê)***""\r" R"***(< Ç9§ {dÑÌmØjÄàÓ¼¯öZ\Ô]€r3Tjª1¾_?v/ı“ORHæ—8«MšÆ£#ã®(*sÒŸ3Eh®Ñª’#XùÎ1OXóïNUÉæœ/J55S°ÓÑÇzO,tÔ¡r)***""\r" R"***(Nyîk„^_v”!éŒT¥éM«M›FbøéšQ'‘ŠU,;SÇJfªb,`c4á)***""\r" R"***(
XtñÏziØÖ5xŒæ™Î8¦3“É?­&şû«ø™@ÿ $=ˆşOÿ ®—Ö¢ó}Ío¹«ä)Qd‡â£#ûõ˜\ĞK‘‡²$Èşı5ù<5%5ÈI¡GPT®+6Ş1Mc“I’zšBH<øÖª(~Àvò  ’zÓr}V¹9\¡ì…ÀíúRãÜÓ<Àx'ò °ş&Ÿ)>ÉÚaA\õ4Ğøèh.ÔÔJTÇÏSA\õ4Ì·­.O©§ÊW±rFM5x"€XœúÒìoZ,
—Ú#¥;aõõ4Ò¸{1ØÖ ¡Ü(Áô¦3`à
µöw·ı¡Nµ>¤~»»T¢5H’ŠŒ±êMÿ Úıi¸ÙR«míLW'¡/½5TÇ1$ò1M'Ÿ¼)KpI50=ÿ :®PöcÁ$õµNhúÕ¨ÙR1ÇlÓ7ÿ µúĞŸâıiò‡²h)®2:S©
äõ=*ÖâöqJ††O•aìû\•æ–£ÉìiëÈÍ>Q{1h¢ŒQT¢ÎÁE!`sHd±«Qdû4+®3Iåæ“ÍúP\‘Ši©
Ê È¦ĞO©¤Èõ«å³°´RdzŠ\ƒĞÕ$/f§Zcg¹œW=Í&ÁêjĞ{46’zR°ÁÅ%hıœG© c4dzŠnHà¨úĞãÅRW³NÜÇ¾)ƒxâ”ô«KPP@ä
isŸJç ¤7;‡çZXµL7ŸANRÄg˜x8Í#¡§È‰
ÌsŒô¤çÖŠ $gÔRT sK±›œâ€ÅzS†îøªH\ºŒ*zu£i¿J~G¨£#ÔUØ¥†`ú0})***""\r" R"***(?#ÔR9éK”j)¥
[¥'ZUô4rD_/'
)***""\r" R"***(;¸¥POCO<ŒSbä#¢Ÿ°zš6SSvƒ(§lQÔÑ±OCEØr¥
[¥;`õ4Ò…¸rè4¡æ’W=Í©­cQE?`õ4 Ó»()FM.G¨¤*j6ST>Ah PlP
 ÀàŒTx#µJÀƒÉ¦°ÈÅh 'Ò•ÂsHF)Tá…pH0})***""\r" R"***(!u%5Ï¡I\mc½U­ŠQÔB œšMƒÔÓ¨¦_(İƒÔÑ°zšu*ÀÅQT˜ùP OAMu9Ï¥;$t4ŒAµkQE x§=ÍZ±\¬m>†ÔµCå#Áô4`ú’Š”ĞĞc$äƒRQZ"H¼±ïI°zš{ıãIM7r¹Fì¦ƒÔÓ¨­yƒ”nÁêi|¯cN
[¥>ª-ƒ‰@OÒ”ŒŒSÛ¡¦`ã5i(o—Ï^(1ñ‘OQ“N*1´Pİ˜¢!:š HSĞĞÖ©JæñˆÕ\t`úT€ÂŠ|Æ±M˜É9 ÓLx8©©6‚sŠwFÑÜŒF;f”)5'…)©jo‘àú‘A `v¥ “N
¥	ØÑ+Áî)\Øà	è)J‘Z§ch‘:bš±“É©ˆÈæU&ãfÆ,|äÎ‚íRPË‘ƒT¥sx¤3g4…u‘KV™¬v°úŠzÓÊ3HMj†±CXØJ"ïƒN(sÅ9F)©Å…
zRàúSÖ<“KŒqWÍ¡´PÀ¤Ôª™ëHŠZ}±²@İÒ¢o»RF)„pj–Æ«b0„ö§y|ã€u§¢Íb@UÆ)***""\r" R"***(>†¥dî)***""\r" R"***(4äU§sukàúRì8ÍJÔĞPcŠ´Ë‹!Ú})***""\r" R"***(9S#œÓºR¨ÉÅQºl@08Òí8Î)à 0(Ò’™¬wĞP½ÒŠJ´îtDP¤ÓŠKJF85JF±‘R(Ú})ã“ŠÁÅR‘ªw€ç8¥pHàR“ŠU\’	«R6Vr(Áì)û©¡T”ùTµR)Ø>†œ/JZ£T3ĞÓ—…éKNUg4›±k`UdŠ]‹éJ(ö¡;•¨m#±¥ÚŞ”õ(ªL¨²2ê(=?‘—k =ZgDH˜İ(Øqš}¢ÔŞ2±ı£9£`õ5jÈŞ-Á=r)áBô¥Ù¸fšv5‹"1À£`j@6Ò0ÎX®ftFBóó
Pƒ½*}ÑKM;˜›©¦”*1ÊŸEMc  ‚Š(§Äi,	¦˜şlõ©ƒM «ãµh™´d7fqFÒzfÿ v‘	Î3WwcXÈhFÏøÓ„dõı)á	R§zi³XÉ¡ª„tò¢¤¤*	É«[©;:ääÂ!<àTŒ€|Â…8ªNÅÆC<³ÜÒaÚ¦Ø¸Å&ÃØÖ‰³xÌÈ§…'¥.ÁïJ/Jq6ŒÄ+´‚¥nTâ”€x"?2şUFÑš îéN`Xpi@ÉÁ§ÇcTšfêW!*sÒŒ7¥IÄÑTm)***""\r" R"***(@Fr)ß…*¨n´à€U&#+•äÒ ©6/­Sûß­6Ñª˜‰œç RFsH ”zŒT)***""\r" R"***(M€ŒZ_#ŞÇzz‘´)±<£ƒ¸Rl#¸©”–4×R½R7ŒÙv£Ú¤ ƒHœÕ­ÍTÆìÈ½S”ÿ jQ•9Å]Ùª›CV6´õLõı)FHÉ¥§ÌÍ#6Åq)UAŠ\€zÒÕ­Ô†2c)<½İ@©2:fôîÍ#PŒ!^1KƒèjR„ô¤*AÆ*“Fª¢cT`gÖƒÔRwÍH•HÑT8òO©¤9ì)…˜÷¤¯ãü´ö=Çå¿»úĞ>”Ê?|ìPü¶~í
Xu¦QG {K“êi	$S¶ö¡œãMA±C²ş‚†<•Æç‘Iæ{Såaì‘&ÓıÑM#Ôb›æ{Qæ{QÊÁÒ=3ùÑå¿çI½}ij”	öB„aÔf§û´QúÒÔÔX{/ Ãzş”sê?*BÌ9ÛúÒäUr0ölr–ÏÓòş‚£È?¥/›ş×éO’à©1ùAF_ĞS„ôoÒ—szÑÈÉƒdòß¥1ş¦X‘÷©ÈÅZŠbGøS×¥'—ïJ9«²f(÷¢¸Éè¿­¡ìÇ… }ÑO¦lRùÔr•ì¬8ŒñM)œÒa“ši™ˆÅ>Pö@A#ı)
…3I½½hŞŞµj6dĞ”¡[¨¤ëE_+aì¢=C´´ÀÄt4ªY†7t¦¢/dÉÎ3Ú›Necß4›NqŠv³N8o¤åM‰êjÒ"—ôİ§û¢’ŠµäBí?İ «
@HéHÍƒÒ­!{+‹E7Ìö£Ìöªå³Hq Œo—ÏZPàñŞ–­DN|¿zP è)iÁ€è¿­;j.F Cßğ¥òıè.GUıiœñUËptÄo”ã¤$Ò—Á4Òã°ªå¦Ç…b9loJh”€)VV&šƒ²åûÒ†:Ñ½½hÜŞµª„…ìĞÓœŠfz’ŒŒVª!ÈÆR¨9—Ë÷¥§Ê.F-QJÌ9R:Á8¥¤,Z¤S»ÃiÆi)K“IL¿f.TëN^1íB}ÑR'İ‘¥ ‚ŸE-GÈƒÔï/Şš	)Şgµ)***""\r" R"***(\=˜y~ôy~ôyÔyÕh=˜“šhP@§ùÔŒÛ†1M+Ù†Ö=¨ØŞ””à„õâ¬~Í	±±FÆô§‘‘ŠaB)İÙ†Æô£czS“§ãKEÉqHaRM%IERH\ ½Ò”zRP	)!Ş_½5”ô4OZ*Ò%ÄiLæ›RPNVƒå#¢¤ö¢„Ğ’c“ĞR4dŒ‘Ú¤¢´L»2/Ş/Ş¦¦?Ş5IÜ\©ˆ)¥2sšpëŒ~¤•KB”Fy~ôy~ôê*®‡Ê4F:u£Ë÷ı)ë»ø}UìR‰—ïM ƒƒS±ÂšeTYi4GEIE_1ZÚÇµ”ú)¦™-!›Xv¤©	'­hTÙ+(XÉëÖ¦¢©h>TEäµœ‘VîŠZ®aYˆøëJ±çŞ¥¢¯™";ÒlcíS‘‘ŠhLæš‘¤b†ÁÎijJ)½¢’dL7fGÏ­ME
v6W#XÙiÂ3Œšw4ô$äš®k›ÅhEåûÒl9ã§­OßƒƒEÙ¬b@cù²ãKåç0œ
pCÜÑÌl’E/ŞœŒsRÎ)Á23š´Í'­<TÔ‡?…Rf©"¤‘LdÉÎjbëEZv5‘–ÊC” Ò¦Á( ¦ÕÆGDlÑ=©ÁsN§®ïâ­Q‹#¥Îje]İèa´ã5JnÆñHŒÅÏLÒ¬xşTìqÔAÈ§Ích¡¾_¿éG—ïNç½|Æ‹A¾_½Hcã­9z¥9:¥+›EGSJzTÄÖ‘#­;›-HBò)À`NQ†Á§?İ4Í„l	
gJ’œ#$g?¥Z‘´HÂzšV¹©pq´â„ûSLÖ6evŒÀÍ:TşÔ‡9ªæfÑĞ‹Ë÷§Šz‚)***""\r" R"***(-ÆÑØˆÂO õ§`1Šxô©©Iš&D±g¶iş_½:Š®fiF˜øàÒ;°iäfŠ¨ÈÕ]1Æ€	8ŸEZ‘¬d0.N)àĞQJ­·µZhÕ\ww¥òıé‚r)***""\r" R"***((sŞ®ìÙ7`òıéÊ§  zP3:Ò4LzŒZAœsR¯Aô¡=KNà½ÒŠ`$t4ú´Ñ¤U˜7Cô¨êFèi‹Ô}jã±²CJ‚riy9¥MEZv6‹Ô‰WiÎivîã©(§Ìj®ˆ•pxïNe+O£i ı)óA¸$ç© O½JPŠiMÀ°üê”âõJA$SÀÀÅ8Ïj¤õ7ƒ# “J«¸u§ĞA$U\éƒ úÓŠ0íO©¡úU#tÊädbšS)***""\r" R"***(JÀ‘MSÈªNÅÅ‘„lóJc=›pÆ(S´çiš¦Æªí9Í;czS'µ-h™q–£|¿Ò/ŞœI'$Ò«mÅh”´#(Aâ”!Ç&¤ÆşsHr§ƒM2Ô†ìÇëI³œsÇ½ ‘Ò¬Õ67`Å	ëÅ:àF*Ò±¼&Eåûş” mÎiá0sšq¦l¤GK³ N	ƒœÒĞm2=»¸Å&5*Ç¥(GNj¹™¬jXŒ!=x¥ò¶õæ¤BNsKBw6B"ƒµ'—ïR³m8Å
wâ¨ÓÚ25‰²5"go4´àøÅ‘˜ÚpLŒæœFiÁ;æ‹Øµ @QJÈ­)éAu Ú5„çG•şÏëRR“Š«šªšˆ9J÷©vôñJ9ªLµRäb0x”DËïR¨Üqšr®Şõ¢ÔÑNÄb"FGZQ:Š•Wwz_/Şªö5U,D°Œç¥À5*£¥ªÜÑT!òğ0x4÷©àãàr3A¢™ˆ÷§¬?İ§SÃn¢ØÒ5<ğ“IÏ üé{Ro>‚¿9Oó[ØçĞ~t¼Ó7ŸAK¿zj£qÔTy>¦ŒŸSG ı‘%.â8˜¬{äÒ±ÀäjjºB’Ç¨'>ƒó¦ùŸJ<ßqO^ÅçĞ~tsè?:o˜}¨Ş}ìXî}çN¹LIê)Û›×õ£•¡:#Á'ªâ†=¶š7ZiN1G ½“€>á™=…^:ŠföªPaì‡ÑH­‘É¥ªädäàMÁ=*†?ZN"öVMbAá‡ÒíšiV=qT ÈMÍÚ”Ï?ÊšF)***""\r" R"***(.O©ªQ²¦z6QI¼ûR‡'Ò«‘ì˜›¨§äP(æK€ŒHtô¨ËÑiî	änZ¤¬?f7qşá§ÔQUËpöby~ªiDd€ir}M>¦Ÿ+²aƒİMŠôZLŸSùÓ›8çÒ%Òf ãm4É“œR°ÈÅ0ŒU(‡³“ŒS‡NµëN.q…ÎjÔIt“E4'‘NªQdû0£ õQT“fÄÀô`z
Rxÿ ir8§f/fÇ`zQLŞŞ‚çĞU$Åì›E"’z‘KT¢/fĞ»Xõıh ƒƒFæõ¤É=Mh¢ì>@Àô¤ÀôÆßìŸÊ©BáÈÆ° ô¤§ätşTÜıÓV¢Å±2}MILØÔúÑ‘…í‡ÔRlj­‘‰E.¡¤ÁE;ˆQEX|AAäÒŠ]Üc‹)***""\r" R"***(A)***""\r" R"***(Àô`z
Zr G"§Qò!8ÅH±£šJr¸ì/fƒaõl>¢—xô4 äf•ƒÙ¡¥ É¦Ô”`zU&ÑJt«÷©ø‚ŒJ,ØœX`z
F`
PqÚŠMXÍéJŞ4ê(+qÒŠ?J)ØN"ªdqŠ]‡ÔR§OÆ–Ÿ)Ÿ(Ï,ûRì>¢E-•)***""\r" R"***(ŸZ
ÔêvÃê)ó•ùOéFÃê*j0=_3*!Ø}E¨©°=5ÀM1ò¢"¤rhÁô4ú*…Ê†l'¨üévZ‘ 9È¡“'ŠiØ9H¼¯aG•ì*]‡ÔSHÁÁ§Ì+22¡OAF¥IéM(sÆ+H»–ÜAF §ØÒ˜Àëš¡ÙŒĞS¶QNÀwAf3Ë>Ôy^ÂŸE1†<v_û5(R{Rì>¢©6†¢EåŸîŠ<³ıÑRì>¢‡ÔSRÔ9Q	L)***""\r" R"***(?Ùı*u\uÅ. «RĞ|¤<öy^Â¦Àôı)vËMI‡-È<³íK°úŠ˜¯¨ı)0=*Ôƒ–ÄE=)***""\r" R"***(&î?*œG‘œ
]‡ÔU&„â@#ÇcC/ÛÏÒ¦Øi
â©H¨¢(‘œsJ±6y- ãš®m)***""\r" R"***(ã2¼r(ÛşÏéRí-Ú†P¸Å6Š *ŒSü²=*A=?
 xÓ±ÑªàsK€zŠP¤ô§*€9¡A<
R§à‚ŒÛôªLÕ"0£²ş”ğ9áì)vQZ&ZCBƒÑJr0EI€:
j£U±Œ“É£Êö6Õô¸‚ƒTˆÒ†â§Àô×^8JF‹B#Å* sÅ<N(‘Ó¤YºÕ	A õæğ)“È«LÚ:	Óİ£~x§‡Á§m‚©3x1›G]¿¥‚¤À=EAè¿¥RfÖº«»½? t#¢ş•& «OQÇB24İ‡¹©¶ƒÑJ_+ØUs§b¹ Q°‘ş5>ÑıßÒ•SÛƒU{Å•ü¯aN ŒT­ì?*@„ERfÉÙ‘á}8) äSÄyşùS•1j”•Íb@ ô¡—#üêVŒç"/¯5\ÆÑ"òøã­[TØ”¡7ñM;š¦D jB `QéTS#£âŸ€)***""\r" R"***()¢©3x¡ƒîJ“¦(ÀôIØÑ;
Oj
OéĞQT®ËL`œPÊW­; ) õ¢ØÖ.ãK°úŠ~¡¤«æ4MØE‘ À8¤QÇ"£,(æ..â{â½Ò— õ$õ6ˆÅ]İéàĞR¬dŒt§à‚¬İ4G‚:Š6JQF¥Z¹JC $â‚„tæŸœâjf±dtSÙ3ÛšELjî“ ç"€:
0AA)­M"ìÆ8 ğ;R`c¥8¡n§š6{S±¼Z·æÏ¥Ç8§€;K·œU­)***""\r" R"***(ã""÷E8!=GçOÀô§*ñ“M6m‘ËN*Gj‘G‚;U¦Î˜Ìˆ¨=©­p*b ÓJÕ¢lµ$D?ÃúRù^Â¤ Ÿ”zÒ„ óƒV¶4Œ®DPŠ“S„àKå{
«ØÒ2±M¼0¥Àô0Œ½Mh½¿*¤îj¥r§9¥ÖœTÔ˜8Î*Ó./PÀéŠiCÕ*€W‘K´‹úVœÆÜäHŒqÖœƒÆ*M†œTc¦¤R›!ÚÙÆ((EHr§sIŒu­¹¼f0N)vQNÀÎq@8§toÜEVœRÓ¶QB¦4))***""\r" R"***( Ôï,ö4ìAJ †š4ŒÙ—¸ Dİª`=@¥ ”]šÆdA¯éNòı…HªzñøÓ± U&hª¬Ly"œ#8ëOéĞS×kŸ¥'sXÎãL\v Æ{àÔ¡1É4â¾«úR»5S+ìÿ gô¥ò`*lOÒ—ÒÙjd"&Ï"”FTå‡çRh «LÖ3dj¹<OUÇ\Rà‚•HE]ìk ì(©  ¤()***""\r" R"***(ZhÖ2Ğeï,õ^iÁê¿«RFŠh`<ŸåKå±8*E8Fq‘Šw-L‹gû?¥(„õ TÁF:Rè)ŞÆŠg–’ßäÓCç4ã =©7î
şKöv?Ïob˜¾aî(ÇÒ“pşà£pì1UÊ…ì.Ã¨ »¢ÈGS@v<ƒUìÃÙ$=Kwãñ¥ËíLGZr9#Š—NÄû!wf“Ë÷§9Á?¥&õõı)rè‰°ÿ zŒ8>´»×ÖëëG+²bşõè>•ÿ jxvÇZN²hµv4İşÔ¾sgÕ6/dØl_J6/¥sQç5>IØ°
àRçÚ“ÍİÃQ½}iòR1!iÁ˜ô™½}iÈàgÑÊÊÃ†ïâsÔg(ó=ª¹Eì®!FÏ­Ò—Ìö£Ìö£•‡²°¡9Ñ±}(Z7¯­¬^È^”¸ã?•7zúş”ï9Oj9CÙÊÀt¦á‡LSÙÏ^‚›½}jÔDéØo–}¨*GZvõõ¤f\c­U…ÈÆÑHYsÖ€Àœ
¥û1iK0@¤¥Êÿ wõªP¤5‹‚šrÇ8ü©Ä·aBîÇÍV¢O²C@¿éJ¸juùP{4Ö€ÚŠp|b©!:H
Œ”ÓyèEH¬¤t ô8ªQ#Ù¢&Å7czT›ÒéUÊ‘<„ayS¶/¥8©‘IO”N›*@ c±ıih¦•…ì˜QK½¨ŞŞµBöBQK½½hŞŞµk`öbÁ£üšr¨#&œZCöh‹ç4ñõ§R‚Qš«\^Ìi óùÒR1Í8ã°¢Ÿ+f0rq¸Ó¶íšZ)¤Í	±}(Ø¾”´UìØ›Ò‹éKN\7i=ìô±})@¥?búQ±})] Êr¨Ç"EQû16/¥×ó¥¥£44Ì_,ôï+ıŸÖ”;f½}j\Xr4Fbã¥'—ïR–SÁ4Ÿ»¡+ŒÆ{MéR6âöcV0:Òì_JZ(°ùÓÎE_½J2zÖ‹éEÒ(ÄC)v7¥< :QEØ½š
Òàrœ€iÁÆ94…Éa¢(ñ“üéB)èiÀŒtÍ<ÁÛA<ˆŒ Ç›±½*Flœâ’­4G+±½)N9%¹éNé)ÑıÓFÑıÓS€„àPê ÈªR¸ùQ
¯ ÇãFÖ=IK» UcûRÉ9+ROZ("#òÿ Ù£Êÿ gõ©(§v>R=˜<có  =qùÔáT”l_J´Ã”ƒËŸ­Wû?­Oµzâ‚ õW‰•şÏëG•şÏëSí_J6/¥>d¨ƒiQÒŠŸbúQ±}*”®5ÈTy§l_J“búQ±})¦>A‚0z-!Œ¢¥¤*	ÉWcQ#Ø¾”¢>áiûÒ” 8]…†ò9…'•şÏëRQMI ä#òÏ§ëNOQR¨ qNÕJLN,€v¦4}È«ÔRàVŠCQE}€ğ/—´r*aÎM.Åôªæ7„H:Q³qéS2tR#¨ªLÙ+”4†2z¯ëS 9»W¦*®ÍÄ"28ñÇ"¤ E;èiÜÊÿ fc‘OUdŠF?ÃŠiÜÚ(hP:

©9"¤P Î;QµsœU'cDˆ„dõ À@ëVv¨ç‡aÍZ‘¤JÛ=?ZvÅô©hE]İ)s&DPÅ&ÏöªÃ¨LÚ½ÅR‘¢W!àúRªuÜ*]‹œâ–®27…ÈZ<ŒŠh‡AVœ 04ŒŒÑIØÚ*år0zsŞ•W'$qSl_JĞUsÅØ`ˆ78¥X°sŒSéÈI8Ïjµ#tÈü¿zw•şÍIOÀQÀªL´®B±‘ÚœTc S	éŠQåôjZš+˜²rVœ#ÀëŠ—búR€®ìÑn@T´›wqŠ™À4ˆ84ÓĞÚ${Ò”§j]‹éKÖŸ25¤Y#ši@;TÎ <RÙ´^¤[Ò” 8)H`Õ©§q‚<óLhÈéSO
¤t«R-¿Ù ¨'‘Sí^Â†EÁãµRlŞ2er‹Ú&¥L !PNH«Næ‰êG±})6=*` àRmRsŠ¸š&C±³À§,y÷©qÔí‹éOšÆ©ØˆÇÇZh‹Ÿ»V:ÒQÈJLÒ-2=€@U T¤gƒHgÍZhÕ4"ª•»Ò°ã4*¬h˜ª„x§l\à-*ôJ~Ğ àU¡†2y"›°ƒëSRäŠ)***""\r" R"***(“Da<
_/o8© GéEÙh‹jqFÅô©6©íN@	Æ;Us3TÈV0z/ëJ##€µ>Åô¥ ¢­JÆ©Ü¯å³úÒŒTÎ <RÁ­F‘lŒD!ZM£HéR€œHÎ*®kˆ¸éOHøéš(R\gù¬mù`p¢‘¢9åjÅ)***""\r" R"***(Ğı*“ÔİM•Š˜Å7Ë;¿­OMe dU+š)êDcç ~4*`òçRxšP¾«úÖ‰›FW«ÏK±½)Á@9–©lh¥a…èi:Ô„‚p5“¸?…Z±´etDàg¤	‘€8©#¨ }*Ñª’À§(µH¸Çœ ÍZw)LhU#¥X#Ò¤Ø£µ@íLÑ2'Lò4®N1ÍNUOQFÅô«M´mAäß4¢.øæ§ c¥;šÆmªüÂœ´
€zÒ §vn¦†ù#Ú^‚ŸOØ1‚3Nå)¢éJ«Ç T˜\à®?p p(æ5SD` 0(BFAü)ãéN]§ ÁªORÔˆÕ~aOHøô©piáè)¶Ù¬ga¡	ëOò³ÔSÔS¶°íHÕL‰¡À¦!ºqS6v½i1İÇãšhµ1› ÃC(=H¸ÇµJæÊ¢±
ÇÏ#ó§”óéR‚½Å8(*“eÆ£#;óFÅô©zQM3eWA22;Q±½*E ò?8(#îÕ^Å*¨Œ ‘JèIÀ¥Q“Ó5JE*¨b«g OH½©À :cñ©9§^*“4U '&“zúÓ|ÃŒJnáşE,rŸÂŞÍö$Ş¾´›ô¨Ã)àpb£‘‡²ò±ìÿ ¥ sŞòsE>V/b;Ìö îÇÚñÍ¬—CÈ]íëJ÷ÍÃÖŒQOÙ™º7$¥'5sŒOäÔrØÛ ´RdzŠ]ÃÔSQbƒ§4du¥ÜÇ½5ˆÁöªQ²A½}JUnâ¢,æ•XpÃš|‚t´Øœ6FqÅ×Ö£S‘œPÍ´grìI7¯­*¿÷MCæ{S£“”ùØ“+õÜ~”»×Ö£;Ñ‘ê(å%Ó$Ş¾´o_Z` ŒŠ(å²o ıëëFõõ¦†aÅÛÖ—({+ŒÒá½úSCƒ×ŠPËœdQÊ/f8‡ìi
¹ê)ÅÀ<sIæ{Sådû167¥É¥ó=©Æ9J.âöCQÖ+‚œ\v zŠÓ”^É‚îş*Z)Á¢İ„é;E&G¨£#Ö¤{6-&õÎ3A~pi­“Ñ)¤G³`\çƒ@r:óIœuw«H9 ÇqJXöoÒ’;U¤K€»ÛÖíëIEBäBä±Á4¥cH¥GQøÓ·ï`à7czQ±½)Û‡÷‡÷“ìØÆV®)¿¼§±úÒVŠ"pbOQŠZ(üj¬ˆäwcåéKûÊà2åF_ßòª@ıå*îş*QÓšLÿ œU$ÃÙ‹Eÿ •ÿ •Pı›
(È÷ü¨çÒªl(¢ŠW³
t}éCu§‚“»³Š2=ÿ *3íG+FQŸAIƒëM+)***""\r" R"***(S¸´QƒêhÁõ4ì‡ìÇ‚ã¨¥¦	ê3OÏ¨£r]0¢ŒÊŒÊ‹‘…ªøÅ!9=(°ùœ€äSiT°è(%ÇAàĞQJ‘‘F¡¤ÒfN"QKƒèhPC(I!XUPW$Rì_JZ8ïIÄV`)v7¥(T#¯ëN©„*QFÅô¥¢§™Ê„Ø¾”7Ê¼Rı#¨ªZ‡*¸Á»9iHsÖ”¼œÒeıåZ+¡¨&&Æô¤ ƒÍ=K´§‘Š®`å³#¢•ƒÆi6·¿åUr¹B”+œRcÇ4õWBqt¢Œò(È÷üªÔ…Ê»Xv§Ò”ò1G0ZÄtS™ yÓ¸íq ÉÀ¥*GQO„Ö©4‚Ìeı‹FÁêj¹ÒEHª riØOSUÌ>TCJš”*„Ò„ æ‹Üj$kFqŸz_+ıŸÖ¦É¥Ø=Mc!ØÃµ(BzÔ»©¥XÈéúÑÌ+m_J6/¥NPšc®y«R)DŒ Ç!Ï"“‚)Á@éUÌbG±})?º*R€œÑå×4ùDA ëÍœğ*]€ŠZµ;šÆ$%x£czTÛ©¤òÖ©HÕ"5µ)PNH©6SFÁêj”‹I!€``RíoJpPE9W=sT¤‹ˆ„db˜PŠ—`íA@jÓLÒ7!ö§*‘É§sšP„õ¦h„Ö“hÆ1Rl¦‘“ŒĞ¦ÑC@ ¤Ø¾”ìCJ«¹«LÙ*QFÕª@ Q°zšÓ˜Õl0€x4ä/ëJTîÀ§(ÀÅ_6†‰²2£îã¥vœæ¥SRÔÒ:ÔĞı()œq@kh»›Ä†•z­<¦y Ò æ´H´˜´QEYkp ´€ x¸'¥ÇZ.QJª­<ò1Ik©¤HÈÈÁ¤ `ŒqR bšTƒÀ5q6LaC&Æô©B2sFÁïT¤®jµc‘J8íƒÔÒì¦õ4NÃv7¥‡…<g8¢´LÕ2„t£kzTÌ óFÁêkDìmE³ŠM•0P¤eî3V¤h™©‘N¥Áô4ª¹ÎEU×SMÑR…Ü)***""\r" R"***('’}èMš°ÔPG"”( R…ÛÅ9}ê¤Zb$dR¤£anÕ¢lÕ6F8'^(XÈè)àéT™ª›PŠCRRi¦™ªw'œªsÈâ©ü$R†„Ó6‹±})@  ‚:Š0OAWÓw
)Ê¹ÎE8ò1T·6ŒˆŠ‚rEF1*MƒÔÑ´cv±i¶ÈŠw•*‚š”R`g5IØÚ2R/Aô¤(	Í(S§k›&¬.Ö©ÈÅ83¢•”j“4R!*E&7qŠ”)Ï Ó¶ST™¢‘ ˆƒ¿­.Æô©‚FÅ«LÒ5v7¥8(=WI°Q±}*ÍTÈÊãîÓ#­L~SĞŠiç¥RfŠW#£ËİÎ*L`óšríÏš¥+ÆV"ÀcåPqÎ*Z*¹ìj¦3kÔªŸŞ @FiÔ)³HÌ‰”¢šPƒíR¾sÒ)&µR7ŒÈÊñFÆô©¶SI°zÕó)ªüÂ—júTŠ˜<fƒèhæ-MˆÁè´ÿ /Ş†ô§ì_z9ŠS¹zÒ…' ©L`÷¦ùeG5F±„1È¥Xÿ ‰E9c)***""\r" R"***(ŒÓÊ?Âšm)ŒPAäTªAPc‘NH±Îh»4Sî&	§ı3šxFôüèeÁàSR4UÊ2E!àŠ’Š´ÑJ¡AœK±½*EÆq·­8¢Óæ-TdAGuıiBĞT@9àğMRw4V"!)v7¥8.:Kƒêh4öƒ67¥ySÇzr¨ÆìĞ567Å&Åô©i@NäÕ'ĞÑNÄa8ğ è)Û÷4ê¥¡¤j'E)***""\r" R"***(*ôÙùRâ¿™9ã¯`ÅÀ¥Lg¡ 2ã 4¡ÇLb©D‡E£óH\
Mÿ çù	ö6ç¶(ùı©g¸ü©wQG!.|şÔ|şÔdzŠ2=E.FÉ€İqJ)2=E.Aä
9.'I…QG³'Ø±à“×…5úç¡—Ó¸”r;’èsĞ~4 GaøT„ 2 ¤Ü?¸)òéXm»‡÷‡÷¡ì®%' ¥Ü?¸)Cü4r‹Ø´({ÒĞÅ!`)***""\r" R"***(·±¬ Á£Ì†£Ş=)***""\r" R"***(8Fhäb?,yühùı©7Š7ÿ œQÈ/bÇ
]Ç°•4Œæ§98zSä'ÙXF9=¿
LŸZVaŸ»IG).QŒÑFqÏR‰>É€”ªHè(Ş@)CÛòª³3tØnîş”ªI<ŠO]˜ÿ \¤û66 >ßJs`1IMD‡&ÁêhÃ)h8ìiò‰ÂãNGğÊ)=±O¢šV'Ù‹ƒèi)ÁÇåH[ÕERD:VŠ('ªIÈ*ŒœS¶S@@)h°¹›©£`õ4´P{6 P;PPvr>è¤¦›`õ4l¦”qJg••4/f S¥Áô4àF8 QŸö…R!ÓÔfÌŸ»úSÂFÚ£oSV›aÈÄ(¦ƒÔÓ˜‚x€dâ›ZMƒÔÒykRy~ôy~ô¬„{Ö”(©ş_¿éJªQE† 0AKµ±œSğAEPùm>”"ŸEäƒèh*Ãµ>ŠÉa˜>†” <äÓ¨ N"ƒèhRQJ_ĞP“T&¡£ĞÑæJ]çĞSåaÊ„PsÈ¥)”¡ÁëKzV±${HíN@Fr)Ôñµº/éA.ªã¦hÁE(m½(ŞOP)Ù³LJ)w²?*p*G8¤/ga”`úSÊƒÓô¥	ÄĞşU%(Çzzìÿ õT2Hö‘ÚŠ‘±øSÊ?*› ä¸€àæ”±#¥'GåJTÓò«ZSE?`õ4l¦¨|£ '¥8'©¥
¥-q`õ4l¦–ŠÊ&ÁêhØ1ŠZ]§¨.ƒvSG•ìiê£©§SM¡rŒç·çKå'¥H¨äƒHÜô¢ìFyj:PP‘OÁô4„ÔQv>Q˜>†ŒCR(ÉÅ;`õ5WÈUrpA§l¦¤Ø=M^zSL9Hü°zf+ØÔ»Hè¿¥.Óè*¥$.QŠƒŒRì¦œJxUôªR°ÈÂœp(ÃzTÛò¦/Ş›w%¢0€ŒóOÇ¥9P
 yü)^ÄØ£$tı)=?*²Uq÷…1Ôc4ù•ìhò½J “‚iŞXõªR4HƒÊç¡§˜J¨^iH¨§Îi©[ÊúÓŒ\t0E¥1Šqw6I²¿•ìhò½OåûÑåûÖ‰š$È<¯cG—Æ0j/Ş,w5¢‘IÄ|óNÚGcR<S‚uªº4„[O¥L~U(Œw42¢­HÚ*ä+qùÒàúxàŸÒåûÓæ5HŒ!=ivSR cÖ\sš¥#D†ì¦ƒÔÒãœÓ‚Ö©3D´#)èi6ŸhWô¤*1Ò­;š%b§Å!RzŠ”€¥(@y´LÚ,ŒF1Í¥(À &_Ò­¤3i*¦zæ1Şœ#äÖ‰ØÒ$,„õ©¾Xõ5ai…ïŠµ;3TGåz<°:æ¤
.ê*Ô®R¹PE.3Û4íÿ ¥*®ÓœÓ)IW 4¡I"®îô2ã½4Í#-Hğ})***""\r" R"***(N3O¢ªèÙHÒ—iÆjP™Í7ãŞšzšÅÜiô4`‚¤£ t«RÔ´ÆmoJ6pjEPO=©YG_jµ$o”ëM©(USõúU'sdÑSÇ—ĞÔÛ1ŠO/ŞµRĞÑ5bJr®zæ¤òıèæ‹²“!Æ@ÅO¥LŠO/Şšf„-l~"•S¶)***""\r" R"***(Jc0sš´ì\ZåıiB1ƒRŠ*ÓfŠCB)|¯cO	‘œÓÕAëVÊR"ÙşÏéN1®8©<¿z] F
f©²§84» "¤)“ŸéJĞ~TÓ6‹d~XcÒÅ@ÅL¨	À¥d fªèÙ=H6QI°Õ…@İ‡åKåò+X³X»Õ29Í.ÁêjV‹°¦2‘ÍUîk7`õ4Òx LŒæ—ËéB¹¬YAsNï/Ş” yª½‹LCÁæ“i¦
^i8È?¥4ÍS±@¦í>†¤ç×ô¥ 3V“-HŒ)'£iô©JÆ‘Wø}*Ö…¦FÔm>•/—ïNÀôJZFD",õ¥òG÷OåSª©©
p9¦¤Z‘]£Ç8¤òÿ ˆÂ§*)***""\r" R"***(3×¯áT™¬dDÎiBRàz~”¢ Fxü©¦h¦GƒèiL`ŒdÔ_¿éK´z
²ÔÈJqFÂ8ò©ŠƒÔRÁÎj®o‘*qŠp‹·?Jª	éOƒÀü)6j¦@#*x—ĞÔ¦&hòÛ¸ÅR“+™25\õÍ(P)şXîiBqÀÍR‘jVè(ĞSü­Ãå )^)***""\r" R"***(ZfŠCUyéÂåäcëN	¸g5"Æ6äwfÊV!ò½8FqÖ¥òıé@U)"ÔØĞ„Ó™§¦;â†
yP‹ŒÈZ<JMƒÔÔ´`z
´Ñª‘@¥Áô?•H~”í£ûâ©2ÔÑ®N4ï,™© ry¥ÀW1Jc6·\QƒèjTÚF1NÀôsª„SÏ4õCÖŸè(P3”sªòØ úÒˆ¸èjeUÇ&—`=f_µ!
@Æ)***""\r" R"***(=Pqš( ü©Ê ÷ªR4U.x5($µcÏ<Sw¯­9{;ŸËÄŸxô 8î*e'“OzG³±‰&õõ 05åèÜ¾´rº(“zúÒ‚CQ©SÛ4ğàûSä3t,-›—ÖëëG(•hÉõ¤Ü)***""\r" R"***(<lÇ4(•ì…=ii¿»¥J\„ûÈÀg4óÀàSã­gj|†r¤)nÅZiÆxséúÒsè?:|†~É‹EúRmİ.AªL	# Í-7hşèüéÔrØ+‹ŸöÍ&Iêiw‡š2¿İıhµˆtš ™Í.Ãıê¨
\Ê‚]6(M Òœ Æ:]ëëR×¹£J?ŞÅ7zúÒ‚AâŸ(0n¹4…˜ëA`)***""\r" R"***(×Ö„Œİ1<Ïj78"—pÎ2)zöüªír9@ä
Z(£”QëşöiA”ÔïƒOÁã4¹IpB`´¡‚ğ9¤¢Ÿ)›Šæ{RøqÍ%r’é¦‚Š(§ÈÉöaE:ĞqØQk	ÂÀiÁÉè´ÚU šd{1ã$r1E
Açµ;åôì˜Ú)À¨¥Ş¾´Ù±„ÖŠW )***""\r" R"***(4±j8‘ŒbŠ@IŒRõïNÈ‡ ¢œ¨¸â—búS'eII±})èê*Ğ8—ï@LæE2=›
(9íJ„qÇ4¼ŠTÄ¢¤¢ŠölŠ’€G"€öle§oaI@¹BŸtSUsÉéO ¸)“œÑåûÓ¨ÃvZ	ååûÑåûÓ€nëNØ}E=Pr
-;aõl>¢‘J#HƒH9§"„Îy§Ğ—@	æœ«·½-9;óHÍÁ¶"’¼â—Ìö§uéE=pX«J0Èâ@Æy4„à Í-/ r¿8*‘œTóà2«·½Òç“I»‰Ài¦ù~õ!Œö4l>¢Ÿ(œl0&sKŸJvÃê)6QM+”JU3K°úŠURM4_½_½: *[v™—ïJGj–ŠAb-«éJ01Š’”!#4Öƒ±8&FsRl>¢…Lu§Ì.[ŒTÇ½;czT‹·ø©ôœƒ”ƒczQ±½*z)s+ sÍ»GZœ€F)***""\r" R"***(4¡Ïj¥ Q±)***""\r" R"***(:>õ OZ]‹éUÌ¬W*E8 íFÃíBbå@8*§R„9æŸ:&ÚŒP@Á§„ÈÎiÁN8»)***""\r" R"***(×® §„¯4¯5"Ç¢›‘6dEcG—ïS´|u¦2ã‘M2’±Læ›Rbx)Œ)***""\r" R"***(it\QçL}ÑMç¸¦·6ŒBŠP¤Ò„ãš»£h¡´RAÁ¤ú
i—f p(ö§"÷4»Tö«R.1! –8§?búRôªS-$GCĞÔÛ¨¤(psŠ¥#U¡ LæN)JzRªõ«LĞ@ƒ<š<¿zxBFi|¿z¥%cD›D~_½=ãŠSìiUv÷ªL´1ãß/Ş¦e›°úŠ´ÍbÈü¿zB¤T»=èsÍicDÈ‚’2%O°f‹éZó#e"	è)ôğƒ<ÓŠj¯sH·CŠeLPö¦:kDk”S¶QJ‰ÓÖ®è´î2•FãŒÔ»¨£aõs"†*íïA õ©Jõ ¨5qc[°ÚqšLqÕ.Æõ»­Q¤wŸtRÉëR¬y84ï$z
iØè‰
Ç“ëKŒqSğ1šmZhÑ+‘ªœQSl>´ÜÔU§sX‘‘‘ƒH‘RĞN*“±¢d`dàQĞâ¦Ø}i>=j“¹¢¹Ç¥òıéB9"œ«šÑ2Ó]İé|¿zvÍ½Ö†©¡„`â”&FsN¥HÍZw)1_½sSªpi|³ÜÕ&RÄ\
xLæ‡ÔSÂ–éV™¤X„db›³ç½I°úŠFBj¹„dbši4ìö£à÷¢íš)ÔQìE9S¹«Z3x´†*íïKR,jÔ4j¼b­I\ÕI\¨=©å=)T0jÓLµ$EåûÑ°b¦§ÈÎj®h¤WòıéÀ`b¥òWÖ“â«FZ¨0.ài#‚*]††ão^ÕJæŠz(LæÑœñÅ*¨µ¢vFŠC±ÁÎ•FN*U
FZ
ö¤ZÀ RÓ‚zÑ°ĞjÆÒªîÍ=SÒ°úŠ¤ìh™Æ:ş´(şSù©B)8ÅRfŠI‰íJ#=)***""\r" R"***(X‘ÀÅ(OZµ$h¥b%z<–«Òœa«šåó¢¨EÏJ—ïR”1ŠO-Î(»5R#	ƒÉ§*Ü
“=©UAäĞ›-Lg—ïHè æ¤*qš $â«SE2%Zœ"¡©6QJª@şuIØµ2//Ş/Ş¦¥‡äÓæ-HƒËÇÒœ¨qÅL±ã¯J]‹éT¥®†±ˆ•~aAAÛŠ—búSÄ|®bÕR=)***""\r" R"***( 98Luşt¬ƒ+UF¢d§JiA)***""\r" R"***(MåŒñÇÖ°úŠ®ceP¯åûş”y~õ` ÆZBŒ*Ô´)M…#½>>ôêP¹ïO›R”„ ‘(©V3Øb—aÏj9‘¢š±)***""\r" R"***(8&FsRì_J_(”ù‘jHŒR…n T‚28ğ§\®dF:sNòıÿ J~ÃNØ¾”ÓhjV>{cÛ“ĞÒ–QŞëë_rŸÏ^ÊÃ:7½iÁRiw'ù™Bir1:L	|÷ü©@?ÅGËıÿ ÖŒZ9ÅŠ1ß4ğsĞšg^ôõ<døQÈC >¦ŒµFWÔR‚˜å¨ä±×­<r3š@ª9Í.Tq‘SÈC¤-™¢—#Öš…‰öL2GCJX¿Ê”*ç®ißJ®B": $àSğ=(ô£•“ì›HëúR1ĞÓÁ½.$ºc $àS†îæ•U}…8ÅO(½›ÉíúQ³ıŸÒ¤ v¢R=“ªØãõà£K@Æy£”=›Ò‚¹ïJqÚ“#ÔQÈÙ›v¥ËãùRSÔ(èÔùtØÃŒğãE=Š÷¤ÊØü(å3p°€àÓÁÈÍ3	ıêUeéüéré¢“#ÔRä†F/eä=~£ğ¥¦.;¶?~G­.R%H)0=) u4d†QŸ±ĞQÖ”mîi~P=hÔNÌAKOÊú
0?»E»éÜe;aõàõ Œüè²%Ó°Ï-½hòÛÖŸE"y¨`}©Ô y¥Ø§¡¦“ƒE?`õ4¶hÔV4!4»¨©©IƒíùÓ¦5W(Ú=)ëŒ|Ø¥ù=¨#Ù±»©§)***""\r" R"***(¦€÷5JÌ~ÄMŸìş”m#¢ş• éÅ(ïLŸdEEHTCF £Pöl•>ğ§àz
0;
V²
(¢‹‰A…S—gÿ ®…v>A¸‚ 4æ 1ùĞ“íF· İƒÔÓ•Ş´¾Xõ4îP½›åŸZpéFO¡¢™>Ì]†‚:Šô¤$w¬.A”Sğ½0)p=å#£®*LAIè(Ô\£TpiÛ©¥ÀÍ;18	è)UC}iÁBô¥ÀŠå ŒƒKä{Ó€:Ó©òØn8ô£Ò¤Àô ('š¸¹Fò3Oü)ŞXõ§¢)íJÄ¸ŒØ}E¨©vz6SJìFDƒ“ŠpPN0)á 4¡WéEÛF0Ã‘Ú“È÷©0}Z]¤ôşt‰ä#cÒ•W{ N>jp‹¦i7aò‘ƒÔÔÏ#l¦—0¹ò8ÇãN1úrÓ4ğ«•.Bq!Ø}E.Ãê*]ƒÔÒˆÏe¡2yYÌñ·ô§l>¢¤	ıê
c §t÷+”aõl>¢Ÿ±½(ØŞ”{¡È0 îhØ{'Òlğ)¦rìoj_-J‘TƒÈ§' §t.Gr1iD8ôüj]ƒŞ“czQÌ‡ÊGåŸjr§wô©p9à<Ğ.B0‡y_J˜*ã¥9cªĞº‹”€B§·éR¢0§ˆ—µH±ãJ®rZ"1œša‰{
œ¡Áª6\r*ÔŠQD~Yö£ËoZ‘@'°Sæ)@£ãŸÒ˜bç «¸ê8¡cR2E5#EWØŞ¢”GÅOåŸîŠQşUIšÄ¬c'®(ŸAS<…4!Ï"©3T†ªñÒ¦y2ÇÆ@¤ÛÎ
Õ¦R‰OSK´zSÙ08ıiõfŠ"R”8æ¤X€Ò²v©HÑ@®SÒ€ƒ©©ü³ıÑG—şÈªS-E‘R€IÀ§´|r1MU ô«M
•ëIRmİÚ—Ë?İ¢z–£6Zæ¤Ø=è^U&Í#1ÔÒ0pjb Œ­4¨Ï"­;ÅHÍ.Ãê)áN8loJÓ˜´†=©Ädb°{Òª(àşµ¢hÚ$[¨¤høÉÅLc ği¥LV¼Ì¢)***""\r" R"***(ƒÖ…Bj,ÿ tP#äsO˜´ìEAu'–s÷E)Bz­VæˆŠ”©'—şÈ¥(1ZEØ´CJ‘‘Rygû¢€‡8ÇiÜ´ìÆ*sNÁëŠ‘cãŸ­.ÃÓm3hHŠ›°úŠ—É?äÓ–1ÜU«XÕ20„õ¥hÁèãSù\ôyìŠw4L¯å{
<¿¥XòÏ÷EYşè¢ãæd+xÍ/‘ïRˆÆ3hØŞ•iÜ¸É¼XïJ#)***""\r" R"***(Ò¥(OU FsÓiš&0'­5¢öüªÈŒÆ?*kF:V™¢‘YPæ‘ŸçSy¨ı)V,pG¢hÖ-XÎÑÍ.Ãê)åè)Bâ¬²=‡ÔSÕsÓ =…=`éTšE)Xƒiô¤ ÷dÇÛm'’}?ZwFªep œ`R˜ñÈ•MäÎ1FÅ¦™jEr™ã•*©éŠœB	È4`Wò«¹´eb5R½h)»š”Gè3Fİ½±T£4C°úŠ6QRàv€íV9‘Œ
\qÒ¤Ú=.ÂGJiØ¥$EM1¹9ÅN#Öåƒßõ«NÅ©¢7¥8ÆOÖ¦X¹ä~tqWrã$È<²zâƒ;
” ïFÃ»Ú‹ÜÙ2 zQS×Ò“Ë?İ«NÈÒ2D]ÿ 
P¥ºT‚0z­/–£§W5ŒÒªW­9TšF1‚?*
…8QAª’cB¨ãáy Pç‘OPÕ¦†›¸Š0)iáW)vÀRæ/˜g—p)vQRõ§ãÑjD2zâ”'ÔÆSôªMš)ùC¸áè3Ràz
‚xWE©Îx§,@ğ)***""\r" R"***(JS• .xQO˜Ö2D~G½2¾õ.Æô¥Ø§½;²Ó!Ú 
R»{T†0>è¥	‘ó
¤Z‘BFivQRˆ× £hb©\ÕMl>¢œ)ø_AJO¥4ÙjI‘à‚œS*U‰Iâ”ÃŒÕ&5+˜Ö‡ÔSöô§ Õ)¦E°ô=(òÏlT»G`((ŒSæ5ŒÑ	Œ¸¥XÀëúTÂ/lÓ¼¤ôª»4ŒĞÅCÜf—gû?¥Jˆ¸êiŞXõ¢ì¿hˆDyì)Dc/’{:QxqëEÙJC3)vQRö¥Ú=*“¹§1Ãê)Ø‚ŸıÑO 5iØÏš¼ßqG›î*ãnóè+ğşCñŸeäOçAJ$Éä~F«ï>‚•'­Œ^Ä±¹}ÿ :7/¿çPäúš2}M.FO±]‰Õ€zœ²0joSN)***""\r" R"***(Á ÑìÈtI|ÃíA”vÇçQdúÑOÙ™ûq'M8Kî*º7;iõ<Œ—E’ù„ôÅ;põ¨2GCJ»=›±e€ùÿ õÓ¼áıãùÔƒ‘A=Í„{o8xşti'ƒš‡zúÒù¸üóOÙ’è–RøRùÇŞ ƒš]ÙêqRàfè¢u—ßó§+ƒÖ««dãÒ¼*9LåEš—û_­DzPX¦—)Ÿ²d»ÿ Úıhßş×ëQo_ZPAäQÊ/fI¼â 2“Î)***""\r" R"***(GE>R}•ÉÃ.:ÒoõO­9[±jj6²$2xıhzœS¹¤)***""\r" R"***(ƒŒæ‡7L“xô4¡ïLÏ4àPŠS?gqÔd”ÒÀ#£ş”r’é±Ù>¦”;
szÓ”“ÔQÊC¦<?­8>)***""\r" R"***(QÑSÈÈtÉUÉ<šváëP«cƒÒŸIÁ’édzÑ“ëQÒ†aĞÒäbt‰·¯­!~x¨”·@:qÅ.R!Í!›æ{šN?¾h õİšvFn•Ç'M9XKR*’yéNØ¾”Ò%Ób‡Éûß•.Ú4Ğ t´¹CÙWÀ#wçFóè) Î(ªQd=[#$ŠPG^µ(b:PâK¦Ñ(p1J`äP>”¬G³d™>´ğÊ{ştÁÒNÌ^ÎC˜ó÷¿*Lÿ ´i	íI½}i¨‡²Ÿöú1¦ï_ZÀ4rÙÉõ4™nÍF3F.VKƒ;
Pş£ò¡SûÂ”ª’)¸ñNWP1Lıİ*ã-ÉÜ“xô4 äf£'õ¦·%ÄZ8ïEdò6;r€@h ƒM"®iõ:±ò)***""\r" R"***(8ns­!$M8¨=EÒVG³Ôj±ÎNiÛÇ¡ (ÏšvÆô¦´ €ƒJ6£4loJUOï
bölPÁºR3<
u!#¡=i=À–4õßÚš?wùÓÔ¸¨1”Ç4Ô 98£ıïÒ¡²1Àœ*E+ĞqQ¨Àëšz3‘HŸgaÿ '½!ÇlÓ¿wGîè"“èhÏµ;÷t „àP>A¹¢•~còšvÅô¥TñK™	ÓAM9[i|¿zU]½ê[¹.˜Ö œŠ“ĞS™wæ…F3Iéˆc‘N 'Kå·çKV¢cÒ¤G¯çJ7„şt’f<ôâ›‡÷üéÔP‰å‡÷üèPùçùÓ¨§på 	8»Ò•£fEî)***""\r" R"***(!›Òœ€ŒäRÒ€SŠÂå 	è(ØŞ”å]´µ7dÙŒØŞ”¡9ğ	äPçš9€@ "ôJAFqšpCÓ¥>a5pÚÇµ>€01J«»½+²ŒŒS*V8ïM##JcQd!HojW$)å03š@›‡=*¹TYIêiêr)Æ :Ñ±‡j¸³NQ(§*xSš&'5ª‘Q‰)'ŠP€sRy-FÀ84ù”FRmô©0àS¼½ËëíTš¹j%r‡<
UFõÅMå³úÑå³úÕs´÷â‚„t©×Š
T¥©jÄeH¤©`Òl_JĞÑXÁ#ŠnÆô©ŠÜR*ò8¦˜ÈÕH<Šu9“û¢“czVÉ””…Aê*UŒàãšFŒ•iš"#•8“kqRydƒŸÊ€„Tš¹ª°ÕZ]‡”&zŠ´Ó4ŠE<(£bö¬d]¬Æu¥(Çµ?ÊÇğş´»[Ò´¹kr0‡<ŠWP@§ìoJP‡¹§}K l‘Å
­¹â¥hÀ9"…AŸ”U¦ZQ©|¿z~Æô¥òıëX³E±Æ=©Á9¥ ´V‘ÜÑ$  0(¥
M/—ïUt\F€IÀ§ñÆiÂ29—czS½‹BS¶Q@BzÓ©ŞÆ—c
3IR”ÍéT™JâQNTÉçò§³ü5IØ´ìGJš•şÏëJ## ªRW-1¨ÎiI<T…QI±½+K¢Ó ƒN
HÍ(AE8!Çšf‰ŒØŞ”à£Š~Ã´Ú»¾†‰±Bp)Fñÿ ×¥Râ–©6h˜QEf‹qîšeH@<BƒµTM.„N¿…+‚qŠvœæµj¢ĞÔg"†\óšvÖi|¿z¤Íˆ„‚8"€¤äR˜9&”DCUÍcE+lóNQŠBO Ğ§µR‘JwEHpÆ)D)ÜSæFªHh!‡…[Ôš‘aşé¤(sÅZ‘i‘²J˜Æ;O,“È§ÌTÈ€$àS•~aOò”r´ª‡?0­9•“±}(Ø¾•&Åô§AëG2-I{Ñ³w8ıjqn ùiDG¸£›BÔìB«È¥*3÷iæ1œt¥dtÍRfŠ Á€0)@òqOò‡aúÑå³úÕÜµ0QÆ2)B7§ë@FéŠ'÷¸¤Z£
·cšM­éSl^Â%ª¹‹æ"U9äS„}À©<¯öZ_,ãÔù—B£"3=E&Í½ªBzŠ¨¡6j¦F=)Ddõâ¤‘ĞRªxU¦îZ™”?¼i
‚¦Ø¾”†0{Õ¦Ñ|äAvıiBrqíRˆI6ÁjCS";óNò³ü?­<FANÃ §{–ª1_½/”şµ&ÅÏOÖ±½)İš*„&"94Ò¸«ÒÅ“’´ùŠU\N.Æô©š!Üb“Ë÷ªLµ4F ƒÈ§'¥<Bsœfœ#Æ{SNÅªƒËÕqNÈ=)***""\r" R"***(=cp3J"çîÕ\ÑT	)ÊàğzÒ˜‡ašQ÷¦kˆLœÑŠxAEÓõ ®q 7÷EH6÷4aĞSœŠ¤í¸ÔÏ–¼Ïj7ƒÁÎ½ŒïWãÜ‡çÈvÑÙ¨GŞœ“NâB]w“ÑiA'¨Å"©ê¥»šN${1èÎE=zcv*5)***""\r" R"***(ØŠx<tr‰ÓĞR <ÒQE.TK¦(r1Îiàî¨éCÅ.^ÆnÇĞg¥0»Q½½i¨6%D”±ìß¥B4â¤œï.:CÙ»“I¹}i›÷Å rVR@Ş†”15sØzTÆj\LİJw§+cŒTY#ÿ ¯NLvÍ.Te*^DÔS2@àÒTr6G±¹%&G¿åL§*)***""\r" R"***(>F‰ö³ŸZ(¦’sÃŠ9lO²°êrzšh¥?bÑb1iw1ã4”„ŒpÂ“H—E@lôÜ·÷Å(<u….Tfè1Şhşé¥ßøü)´š|·#Ù1áóÚœv8ü* 3Ş¤´œLåI¡w·­9[pÎ*>3F©£•™ºD´›”w¦'øéÁ95)***""\r" R"***(\NšB†¡§«LÔ{©¥ÁÍ.VK§rPGqJXôİŸÂš¡ú)***""\r" R"***(.·çSb6¨úÓÂ€r3×õ§/ÿ ¯JÄû&8uÎqNİşßéM¢©"}‹lzœñ»?…-GNPİGëMÄ=‡€SŠ0¿Şı))¥˜zR³¤Çá½úQ…ş÷éLŞ}(`G$QÊÉöcóãı(İşßéM¢ƒÙšQôÍ53M8)n”íb]$/îéf8ëC.:‘IBLFQJªIö¦€§®)ã§ZMƒÔĞ	¨z“ìÉıÜRÓvxoÎz)4K¤„ ¢œ¨1Á¤#Å=:Tò™:by~ôà01Eíb];R…-Ò™<€¼Sè¢–ÌŠ(¦G+ÁÈ§+œüÆ!#4‡ƒŠarÜ~Gù¹Í0g9åİüT_Ry´ddf—kuÅ â8¡µ`ä1–– Êi@?Z‚ÃÒc‘B‚K‚z
‚\ )5%Ğ})B“Aƒèi0}*J(" ƒN
3À (ÎE=œæ“%ÀLCJ€ƒÈ§íÿ h~t¡=M@¹Ú ' §ì¦€¡zPŒn¡¤©)
s@{1”£xô¥òÖœ“¹.Í¬OJ_/ŞŸå“ÑèòÛûÔ®ÅìÆŒ§4ìCKå“Ğ~´ê›‰À`S”í‹éJ98§ùcŞ‹’à1TgåûÓ–2NFGÖ°úŠ|ä¸ù~ô¡ ëO	êiv
\è\ƒ ' ¥HÍIå‘ÈÇáIJ÷&HDE-*…#“K±}i]\ÉÄTû¢–€¤¥Áô5W+€H”!?ızzÅíùÒm•	±}(`HcÀÏ4Ò¤Pše%©SE P@©Y	ã‚İ«M¨Œ “OZpÈ§y^ÆŸ1j(bõÅ(ô ‡?ız_/+HÈµjGƒèi¬™9&¦Áô4ÆBNj¹™Ij0(£Ş"ïƒG—şÉ«LÕE£Ò¤òÇ÷M8GÀæ«™•ÊD¼R2œŠœ(´…;Ñ”JÆ>:ÑƒèjcÏ+ØÖÉ£E)***""\r" R"***(§ĞÒàú›Êö4y^Æ©4Šåh„)')Â?Æ¤ò½(B½«RˆÂc¢šGByö©¶C'$ÑH¤™ RNı(ØsÖ¦{<¯cT¤kˆJ8æ§Ò¦òøÆÓG•ìjÔ±»Kåîš“k€´ıƒÔÖ©¢“¹¡£ĞÔ…x"“ĞşU¢i”†maÚŒCR`úL7¥4ËW#+¢€ HP Ğ# äZ&h3kÔ'¯*®zæ”ÄzV¤\[D& NI¤1Ğf¦òñ÷¨)èkE&Zz‘"v#Š
œ*_-JQ)***""\r" R"***(RfŠÄK»¦qøS€8éOò½(R0i¦6Èğ})Jxæ¤Oÿ ^”ÇŒäjM—©¥'Rì9Á Bs‘Z&lšcqÎiÔág‘Kå{´Ê²‚z
\CR*àÔíƒÔÓº„ÇZ*g‹Ûµ0EÏCZ-ŠLe=>è§³éJ±Çj¤ìÍ"ĞIè)<¯öZ”F@â—aõ­99¬Cåîš6ŸCSl>´¢ÿ õê“‘—ïG—ïRyL4ykWÌj›#òıéNy0@)***""\r" R"***(8&î«R-H‡búR… ğ*_ xĞ!
x4ù‘jhĞÒ˜ñÎJ”D{ƒKåàt¦Íc2CIßı*,{ÓZ,Ó/˜j}ÑM äñR› 4¡By«M¤EƒèiëĞ})şX=3G”{L´Æ`¢UqÀ§'Úå{iØÑH‡ĞÑƒèja=)***""\r" R"***(?aõù‹SE`¤œb—Ë÷©Ìyÿ :O zš‘JdI?zŸå“Ğş• ˆôå\tÍÚ–¦3a æ§Ò¤O4"´º.3#)•9… R 5(F4»¨¢÷6ŒÑ\õÏåKåûÔ¢<Œó@W3)M)***""\r" R"***(TàsÛÒƒëN1NT ğ)¦R™ÇüºÓNà@Î
œ¡é¦<öüª“5SE?Êö4yxõªE*ˆa õ¤Ú¾•'•ìh»OãWvZ› 4å\õñ)***""\r" R"***(8BÀsV¤Zˆö/¥èµ Œ÷œ#=@ÅW1JdAHàKåîÔ¢2zKåzƒEõ.3D>JÒˆ‰èjQ}i|z¤Ëçµ³ŒR”ÀÎjQ<ÒßÒ©2•DCGĞT†,”¢":b¨¯hˆ°GQIµOjœDÇ“Ò—Éİ?•ZØj¢ 
àS•sÔT¢)ÂzS.5@ ¥©LXààQå})¦jª"**C8ÇåJ"#Tš5B §°¥{Ô¢<qš<¿z­Uª’0;Rà«š]ƒÖ·J«T¹ò^óè(óµG¹½i2}kòCæ½‡‘(›ÇçNY½ê
Uë‘×Ş“.‡ra 'Å9d=ØşuÇL~4Îy£Ù¦dèLş½H®@ªhùïùÔÈÇ:N™.‰+H}ZO7ÜÓ>næƒÕ>Íìÿ 3'©üéw^MFsÚŒ·f£Ù¡ª,6z·ëNÿ x~5sßìñœQËfC Ç‚sÔSŒ™=*¾)ÅN~èü(q!Ñhzœwæ‚NO?•G¸ƒ×ó ¹5.&n‘ b)DÏéQ©9êiN{T¸6fé"Uô­=_Ôâ Šz÷¨pÔÉÑ&ó29Å&ÿ ö¿Zb’3Alõ¦r¦Hş½9]‰Æj%-89§ÊgÈÉ2}hÜ=i¡˜â{Rå!Àx<ç4õ|òJˆ!ÆCS#½KŠ#Ù"BO­ npJ0ÇƒŠ6ãøGçSÊK¤Å£èi>lôô dâ—)>ÉõŸïS‘¹äÒaÎ(BIëùÓåfN›zp'~´ÚpBzñO”‰SĞBÄğE9HÇ_ÎšPçŠP©ildéÜvG­»ıi»[û¢•TuÇ5¬^ÈpÜÇH¼* qŞ¤ŒÒqlŸb?æïŠZfÆ¥ÙƒÁ©å%Ò°êÁÈ¤
AÎêZ9EìÇoõ¡Á¦QNÈ+’Q’:fãëI“ê:\¤:M†"‚I94Ğ~´sê?*V#Ù‹ŸZ2=iB±£czP•ÅìÀ9¡ıE*‚)***""\r" R"***(-]…ÈÅR;æ¤VÇJ`LŒæ•T¯F©±.ÄÒŒÒ•o­¯>µD{4 œ
T?0àŸ6E;aïÅKjÄ:bQNòıèòıê9‘Œm=X·ZO/Ş”:œÒz‰ÁØZ7cß­…Tœ‘JÌf89Å‰4>QOPB€ià"€Kıj@ª ù±øÓiÊø"{4; ô4ß•çƒA'Ó=HtÂŠN}J^}GåT/f ¿ZZ $â€Jš‡¡.‡'Zu"±'Ÿ~)ÉaTÔÒjUPÙÈ¥òıè€À  àæåûÓ€ÀÅ{1äfª¤dm*MK%À}=´ÁÈÍ(~íH½˜ú( rhfä#8É  Ï”FGÍI´C€´¡ˆ¤¢¦èQw·µ.ñéM¥UÈæ¥‹]çĞQ¼ú
<¿zRƒµ.d€§#4¸' ¡Q±Å=r­+±8Ãz]ÏıßÒJ=+²yD§”€ƒÓ4µ-’â @iÉ÷… 8§„ÁÎj[!ÄZ(ëÒŠWDr°¢ŠU]İèĞVb¡<óJT’iUq£ëE&ÈqW`õ4åŒà`ĞN)ê‡TóXN(@0 § IÀ§€T`Š)ó\†ÄØ=M8g ã½(LŒæOšÄX¡úTg§ãRìcÚšÑóÈü)©"–ã)Sï
w”O")ÍW1¢ÜZ	©¥M/–=i¦h•ÆÒ” f¤D8â†LtªR4Š"¤(	É§¸9È¤U,2Mh™I+ˆ(§y~ôy~õiÜ´Ú2CJTŠERFjÑ2Ò¸m,(©“ĞPAš¤Ò.(Š“­pj“¹¡ ô¥ØŞ•IØvd`p)BzšxBO4¾_½R–£å"|€)*R‡µÒµNå$ENTfŸ±½)B`e¿*i±¤È™qÍH©Œ|tÅ7czV©–ˆ¨©„d÷¥01ïZ)!¦FËsMØÕ/—ïúPS9«M£DÙ)***""\r" R"***(ò œšG¨éV›-¢«´ç4à„Õ©jhÈÕCu© $éKåûÓ„ez
Ñ1«‘˜É9 Ó1ÍOÖ†¹_1JäI÷iiâ"yëK´¨éT™¢l`ô§l¦–…è>•\Æ‰òÇ©¥<Œ
”ò)***""\r" R"***(3czU§b“±USiû½(Œ“€j¹‘¢	¤<T«ùÒ”8â­2“¹)***""\r" R"***(ö\ñéIåûÕ­Æ7'ÖŠ“ÊàäS
Õ¬Z±ka)é÷E CÜÓ•OATRvaE)R:ŠJ¤ÍT‚¤¦ù~ôê¢€ò1M1ñÅ:ŒŸZ®b¹†r¦•\“Šu(Ry©2Ó°”´tâ€	éM»”š‡®M:£Æ*J¥±´Zı
mIE_1¢v#£­H'ƒ=¨æ1ã¡© úR„`1ŠQi©$h¤ƒj{õ§Qä‘ïAu¢÷-4QJšcºBR¨àšP˜9Í:šva¥=)***""\r" R"***(*©^´½ñEY¤$ÔQN
Hù¨òıêÓº5RE;Ë÷¥“È5IØ¥1¡ˆà
x”áÓ€ÀÅ>aóØŞÔà t©iB1ã®Ë»#qØøSvóÅM±éHÃ#ü*”‹S#£ õÿ $A£Êe9«‹)ITçŠpOSùSÔn8Í(Aj¹¬ÍØÍƒÔÒÓÄDô4¡
u­"ÍÈéÊ™4êU\Œæ©È®a»©¥
qĞÓ¶{ÓÂ0*“•ˆÂ’qNØ=M)u§ÈÎjÓ-Lg—y¥*HÆ)***""\r" R"***(IE2”Ù•ìhØ=MKEZùÙ¯ğŠvÃê)Àg¥)VEUÚ)L`OSK°zšZU]İé§Ô®v0©íÏÖšG¨©ŠÔÓ=Wõ§t\fÈÎ{S•AÍ=b^¤RùcSOSUU"2„ñÅ¨©<¿z<¿z´_´"À)***""\r" R"***(úS€¡§loJP‡¿H¥PøğÌHÁgû4ÍßJ^M~jàG²°ñ'áNY	äÔ[[ßò§(aô¨q¤É<Ïöi˜Ÿ_jJ(Q!Ñ¹(b;Ôˆã
	=M<ƒÅ$J‹D¾gµgµBF>´õÎ99¥ÊŒ1şgµ8KÇZ”!#4r¡{;’«“ÏZuD ¯ ŸÎœô-úVn"öL˜>iON•8ç#ñ¥cÏ Š9H•6)cŸOjààÖ›GĞRåF.á&)***""\r" R"***(8JO©I=(òÏ­.C9RDÊÙàŠ_¥F ô#?J~G¿åPâbézirßİıiëúSªyLİ=Å(fõ¤£ñ§Êˆt‡	2:R‚O8ıi¡XŒ‚?r®sRãb!ÁBØü)õ:
x\tÍM™›¤…¢—aõ"‘ÈT=ïÃğİJŒnîş”àsÛ­©.˜§š#¡¢ŠfnÇ+1íšx8{ô¦)>ß…?kc¥KD:MæşõÛÖ“ĞÑƒèiYé¡êXõ-0Ïœ3š‹24-(bz·éM vQF¥·'Ù’÷¥.sÅ4(3NòÛ³TÙé
“‚ß¥:˜#=Í.ÁêjZ±>ÉÉ#P(©%Óh(£h=ô£gû?¥=	äb‚GCNSùü)ª™ÎE;`Í&¹§+Á¤U$u§ÀÁ ÔØf( ò( —ĞÓå³ Ç»~”ú@ƒÔŠ‡¸Í&’%Ó“Ò€{S°GQA ŒFn›æ{R«ç¡Åxæ”'?w…&®C¦.öõ 9Ï4l`)0ÿ İ¥b9GyÔ¡èiw-)U=¨±.Ğ	"›°ƒiFîø¡¢‡ì:p ò*1»²ÓÕqÉëŞ¡¢}˜µ 9¨ÁÇztÍEˆtØª@ê)Ì¹äR"õÈ§íaÚ‘." ´T…}Wô¤	À¯¡#Sï
}(‹qøRì¦¤ÉÁ§GŞ” œ«˜ 94>ôê<Ò•#µC±<ŒJ)p})***""\r" R"***(	¡;J#¥;aõ¡F1·ô¡²¥]ßÃøÒˆØô§…'µ"9”¡ˆ§|¾Ÿ¥/÷JÌ9 04õİ€GåMP	À¥9UëA.˜98äSjCâ“åşïéRİˆöbGŞ sB*œñODëƒIî'¾_½_½I°úŠB¤v¡6'1ÈjpÎ94åBiâ.:Æ†KÆÈÎjEÏj<±ëRøÔ²yÓŠÆ—héŠ~Ãê+)àGåûĞªAÉò„P“Ò•Ù.QNAçìAHÍÆÄtª»»Óğ=(CØbô±-)***""\r" R"***(UÛŞ—Ú°úŠU\j[D¸&7czSâ`r GJpÒ³r!Ä(§¢†QNò½…EìÌÜF*g“R#ªş´ÉëúTª‡¸Í7"\n0ò•u©È;zS
ëúU)	":)år0Íhš5Q:şêQ	 Òª`óL¤¬zNx"¹2däb®-šÅ&BÑ3Òˆ&¬*à`HÉ“Ú´ŒË²!
§û?¥?Ùı+X´5HJdç4»Ò¥XNE/•ì*îl–ƒ<¿Ò/Ş¤XÉ<ş”ó	
Ñ;”•ˆ<¿z
`g59‹ƒğ¦‰è*“Z‘'Şúw’ßİı(òŸÒŸ1ch©.z~t¾W°¡;”’#UİŞ†N3RùDvÆO\VÊNÅQRù^Â+ØV€EE9¢ç¥8 (Er‘Ô‡iB3J#'¯éZ-•ˆH#‚)¬•a¡9éHa8åEh¤4Ú+ƒƒJN*³çµØ+HÉt@Ë´g4¨9Çj—ÉÈéúP±°äÒ´M\¥a”à„õâ#Ïl~ã)***""\r" R"***(Uõ-y~ôy~ôò¤P«¸g5I³DÈÈÁÅ(LŒæcúRˆ›°­ïfGåûÑåûÔ‚&î)â2ª½ŠNä=éÕ1…QHbÈè)§sDîDO¥ï)ázv§l?Ü¢H½ş´´ò™ê¸ &Ó’8÷­ÃˆÊ*@ºKå{
´ÕQŒHË¸ç50Œ˜£ÊñùV‘‘]4+”=©Ê5#D{
O)ı+E$Æ¼ÆĞ=*@„Wô£iôª4º°ß/ŞŒñOUÈû¿¥;ÊöîÇBÑã§åM
sŠ°ÑäSx?ãT®h†ÁÎiÁIçµ?ĞR…' ¦U×B6]£9¤©LdõÅ<vˆ©Uww©yşùRùL:
Ö2ĞÑ2?/Ş/Ş¤ò›¸¥1ÀÕ]˜À01EHÊş”¢<ŒàT·rÓ" • àRùdtÅ<(ÇOÒ…¹dtï/Ş"=p?*_)…i{¤GåûÒaÚ¥Ø}E¨£™•ÎCJ£qÆjO/¶åG–GLU¦ÇÌ†‰<_%ªTŒçJSzŠ®b”ˆö7¥Xv©UvıêxŒ>k!©=Í9PãŠ—Êöl#Š\×/šÃW8æ#9¥T8åJpF5\Ö+!¢#Üf¤*†Àâ°zšw¸ÕA‡¯µ7iÎ)***""\r" R"***(NTô"ÄT§ÌZ‘—ïJôÏ•/•1Š<œr9ªR+ä^Xn ¥X™NjM¸íŠP¤Ö—¹¢™Æô¥O^*UR½iDaù'IØµ2‡<Pç•©š¢<éV¤_?b5€ášRÆ¤÷À¥òò=ê“¸)2Å/’İ0?*QÇİ?•h¥bÔÆ*ã½;czSÅ¹'­;Êj®fR‘Æô¥òıêA’)Ø‚š‘JDA9¦´y÷©ü½İ4Äş•i±óÊœšr®îõ/”OŞ¢Øb©2ã2//Ş/Ş¦0âšcÇÿ ^™ª’d~_½9GğŠvÃê)Ê„”ÊRC#“M(J›fGøÑåû
¥±\Ö òıéÕ0‡#%!Käƒü&´‹-Lø¬¸÷¤2r*6|ô¤;¿ZøSŞt	DÄ÷ü9d$ğOãP)***""\r" R"***(Àğ?Jr“ŒšC7D›Í÷y„ôÅEJ­´óKÙ‹Ø“£0êAúSÃÇ][##"¬p@¡ÀÍĞd¥ıOëNW8â ŞŞ”ªüuÇãK‘™:ÛÚ²|½ª¾ãëK½½i8XŸbXŞO"”H=*/NiÛÇ¥.B]"q.O8¥2qŸÆ §½.ãêjyİ"_3·¢BjyÎsNV'Ò—"2tŸBa/=:_0˜ü* 	è(äsÒ—%ŒåH$ àãñ§¬€ŠI=H¥‚¥ÄÉÑE…m83ü_­B²Âç<~´¹tI·ÿ µúÒï=ÿ •B¶?*p$µ<¨‡Deã¨¥ŞsšˆsÁ§ƒÆ‹#'D˜KÓ¥8HïPâ;şu(ÉÑ&ó}Å&ÿ ö¿ZŠ\„{Mßí~´¡ˆ9ÍENRz?:>ÊÃ÷ŸAJ¬IÁ¦Ò©=@ı*HtÚ%QùS–_Î¡ÏaJ7*lC¥r_8ç§ãFâNAüE¸0qíJöÍ¦N“$Éõ4»Ú¢Éõ4¹lg&Ÿ*%Ò&Zrç±@³Ô~4ğç§•™ºDêqÚ¼z…\ä}iÅÈô¥ÊG³d›Ç¡£xô5óè)U‰ô©qM’†–£Sƒšvñèj[³¸áÙ§)#¨4ÀÙä\ŸSK”‡I\~ïöOåKzfX÷4™#¡§b]4LÓò¥Ş3P‡=?=r}èåD{2@OcJvæš¹Ç"œ¤ƒÁ'9õ<g²ÇÊP¤ô5Fny'©4Á8¦İó@8íE‘JŠnñèh)***""\r" R"***(Æ &…lšJT Er¦‡ä†œ§=@¦è)Èê)37LR€Òô4êP¤ò*Y°èiÃ=éÛ¨¦GQHF ãµH:Tu"ôJâ9_iù>¦˜«×+úSö‡c' Éõ4!ç VŸéStŒÜŠ(¨z“ËaAÇaJ¬;àR'µ9Wq@¹_4¦R¤Ğ~T`zP'Â@G?¥8ŒÔx § <ñRâ„à8v§€1œP )jLÜ[ c¥9r4ÔM9K‚‚yàz
0=šÌ@Àô¢+nëÅ9T“Òr‰J€ÈíOÚ=(ÀëŠ–Ó#bªç¦)v0èi1èjLCSr9Í¯ıïÖœ3Ü
\C@BhºKŠ¤áı)Ùã¤QŠ\J‹á`© úS #øJxéH\¤˜”i 8ïùÓ«;³'&ñèh	Æ(*j r(%ÄZP	8$ô¥U æ‡¡”¢
¸<Ó©Py©ø‚¡³7¡‡B?JUÚÃ;hÚ¾‚”/ ©{.€;S¹Å
8ä~”õBG)***""\r" R"***(â*©ûÃáœsJ±)|¶=*3q@ÇJ‘‡jj¡éS*•ëRÙ„l¼—ô¦`1úU†RF¦ì8ÇJCP"UÁû¿¥?ĞR” f“óŠ´ËQAF ¢ŠÒ2(R©¨¤¥Mh¥râˆ'INØ}E*¨‘V¤h’oJkzw§“ASĞÒ´‹)! Ràz
1ÒŠÑ;–•ÀqÒ¤ ¢›°úŠuj™aè(ÀôQM;	«† £ĞQEUĞ%`Àô`zR…'µ*¦:€i¢’li£ó¦0¸+‚Oµ7nz¯éW$ZB.É—ĞR„8àb—aõ|Ã±Œ“Ú“Êö0P Ràz
|ã¹Q”¸ ©6ƒÑJS°«R‰è)
‚8”‚:Š*Ó(aB£µ.Î”ãôØ
Ö/Qõ!uãîÒ`ú™ÇôÜCZ¦iHÔÔfŸIµz€)ÅHíUÌÍTn1“' ¤òÈéŠ)=)Ê¸Š¥)"­b0 @¥ÁÆqR`z
0:b´Œ†ˆéA#¥)C1FÃê*ù‘I!Ô`zQ‚z
#¨«R.!è(ÀôPN*”Š¨ãùPÊãñ0yªŒŠ‰B½åJ€äT¬¹éŠo–GLV©š&&LS x©BzÒyJÑ5bÓ"§¨zS¼¯aG–}©óšb`z
0=;gy£aõ¢jÃ€:
;¾´í‡ÔP#'¯éM444‚:Š0jQF¥ksDÈöîş”T˜”…AíJå]¢°ö4l>¢©60\7P?*u"©^´ı‡ÔS¾¥­†ÑJA’˜Ç)^„Q³¸"…BiÁHÁ¡H´ì4!”à è)àr)BËúV‰—Ì"zRœ‘N€9ı(1xıi§a©ì9É§`z
R„P“Ò©;”¤„ ‚ŒAN‘ÉS°=Rv)IÓ—)***""\r" R"***(ÔÊè(ĞSæ`tÅ©È¤ç+NÙşÏéG0ÔÆ*“ÎiBÔøSÂp1Jç­Re{@Ult(ROAøS•:ştåRM;‡8Xƒñ§*©íùR„$fœˆÃµ.k-
SÇè:BŠ”§¡£aïMJåóÑÏ@*S=¿<£Ôb­¤E´ÿ wô¥
Oj•PƒÎ)vJÑH®r0=T~ª•H7@(ØW·åUÌZ›#¥ Š~  /Ò­Hµ6"·¥.¥(CJxN:gğªM¤ˆéCzùSöJ0=Zes)***""\r" R"***(§ÚKå{
Qg‘VŠRHB¿¥JS?ÃúRy^Æ´M)***""\r" R"***(NÄa8–œb1øQ°úŠ¤ĞùÄ;­8mnƒô¦”a@V=8¦R•Åq”Æ`8"¤(Oß¤1ƒÓõ«[ÆDaö§v¥ò½…Yö¦R˜¡”E“û¿¥(ëG•ìj•‹ö€Oµ(8?ãMòšŸƒèjÖå)3á¿4ÙúS¼À=jÌ3FóŞ¾?Ù#ô`N&ÉëùÒ‰3Ö¡SÔääÒtŒåE"MçĞS•‰ëŠfí¼æ…q’zÖnbJ­Šr¸ìj-şß­;ñ¨ädJŠ$ÜO|ÑLŒRïã¥.S'E@Æ)KñÅF<cõ§‘ÈÅnˆàçĞSÕ±Î?ZŠœ$ö©äfn“$Ş)ÛÏcúÔ@†èiÁXâ—!›¤‰7ÿ ®œÜÊ£÷_Öœ§*\‘:ÉÎÉíLVÇœ\v¨ä¹Œ©
ƒÀ¥ó	éŠa'¯JPIíÆ“›¥bPHéE"œ¹ü)jL-G+(éN<Šb¶8Å<g¸©å'Ø1Í8?£Ttª2zf—).‰ ƒÈ©|ÃÜT#¥9YjNnŠ$2ñ@vëŠm­CV2tPğÀğ)AÁÍ7wû¥*œ¹¥c7E\£õ§:ùÔ`‘Òœ¯¦¥¢=“CÃ°¥zŠ` ô4´¹It¼…gÈ$R‚çi8=?*2W88ö¥Êe*H\¿¥.ñĞÓw·­s‘‘EŒİ+üãO^)ƒÒœ¥±Ò—)›¦Jÿ -0}3O©³3tÂ€psE¬CƒC„„u¥¦˜N.Æô¥dO(ğÃµ(qü_Î˜«sÚ€¢“ˆœîG?úşt ĞRìoJ†Œİ1  ÿ õéÊÀ`)¤`àÒ…')r’àIæZp`x¨Ô0iÊ@4¬fàJ»ñÚ‡¦«®=©Ê»»Ô´K¦8°èr)¥@ïúT…Xv¤ñJÄ:HfÆô§.áÁíéAVâ¡“ìĞ”äëĞt¤@	äSÕ9ùEK!Ó HèjNiªŸŞïz–fé¡€àƒJ­‘Á4‘ƒ@ t¡$C¦…ÙëùÓ€Ü>aL§)lqÈ¤Ñ˜»Ò—¥ úŠpõ\úTàÇRäúšJ]éPCˆn#½/˜{ŠB¤‘IJÈ—?Ìôo†š£'‘NØ¾”¬ˆtĞ¢C)***""\r" R"***(9lá³HŠ¹éOTşèª²'Ù¤<.3ÏZBƒµ8ƒŒâŒÔY²loJräih8¤îO õ9¥¤#4í¬{TØ‡Š7À§†+Òt§ì_J›È-“Š]éFÖª5'”6·jrïšüóJ<
—±<–
U hØŞ”ª¤E@5 ¡@è)èIëB zŠz®îõ,‡%¥jUN>aRC‹Cié÷EÒ” 8$ÂHéL© úTÈ‹11éŸÎ—'ĞĞ4â„‘4†N)ÁH Ó€¥ p)]´ª<Ò¬d*pŒƒµ‘”£qĞS€'¥*©‘O ‚§™éŒlÒ:
‘bÈéš_+ÃúÔ¶¶€È©SîÒ*qó
z§=8¬Û1šT’)BĞS•84à Vm™ò°UéOUÁÉü(	‘œÓö7¥O1-)***""\r" R"***(*	ÉŒ£¥Ø¾”Œ .@ªZD;wqŠ6•8§àg8¥ÚXtâ´Œ†‘&Gõ¤òÏ¡üê+ıŸÖƒ•­¬]‘ÇÙ§ªxS•?º?Z]éV¤RCv/¥5€)***""\r" R"***(Š“czQ°ã?¥RÔF¨ qKK±½(ØŞ•¬dh•„ ´›Ò¤¦—Êÿ gõ­‘C
°Å%L¼R4|ç«R°QRÉ9+G•şÏëZ)¢ÒD`dàS‚sÍ=PƒÈâ±})ó"¬¬0ÀQO
ÈlSÚ­IˆúœRà{ştöˆi»Ò¬¥k	ïùĞ åN>aK±})ŒEU#8¥Ø¾”¡N8RìoJ¥`°€ĞQKµ½)Ddõ«Aa¦2y"“júT¬cµ3czV‘¹J7±}(
ANØŞ”G&­7r’hc€qŞ›RmİÆ(1’0V´ORâˆÖ1œ¨§2g ©R2zŠSVµOShî@## ¥TÄ*]‹éFÅôª¹Nä{Ò‹éRl_JQ# ~µI‹^Ä[Ò«éRù_ìş´É¯ëT†›" /½)Œ«úÔWû?­.ÆôªM£DDb’¿­ U TÅH"šT’*Ô†5[1SĞR²qòŠ~aV˜Öâ óNØ¾” ¥­¹ªbl_J6/¥8.sHAjÓØM‹éFÅô¥¢´MM‹éFÅô¥¢©-„Ø¾” ĞR…'¥<DGQšÑ;)***""\r" R"***(˜ÉäŠM«éSb0E'•è¿­]Ê»"Ú¾”€*_+ıŸÖ+ıŸÖ‹Œ…cå*óó
›Êÿ gõ£Êÿ gõ¦˜Ó±Œ‹J÷©dtª¿ŞIš)˜Éê¿­,…ıj}‹éFÅô§v>dFª$sN
O S¶/¥9cÂã5I¡ó"=éK°S¸û´ğ‹EÌNdK=©J‚y0Œ‹úÓ¶/¥h¥ ÔÊûÒ€€œS²
hˆƒ¿­4ÊS#*@Æ8¤Ø¾•0SE;búUs¤ŠûÒœŠ¸Æ*m‹éJ±«~œŠçDj§QK±½*`€u£búS»1®"ª{T›Ò‹éT˜¹†  À¥M<FÈ­(V^‚¯›A©¶Šr3‘KN@QJå)ëJQQNØéKBfŠc
ôúÒcëùÔ˜'Ö“ÊbrkTËçC0=ÿ :T<ÿ :•şÏëJô<U&>d  tu§‰èi|­¿xV‰–ª"=‹éJaOØ¾”Áè?Z«®…ªŒF9´¡à
Pƒi¦‹S#(ç±4¡9(›TóŠ¥"ÔÆT””íéWvZ˜”RìoJ67¥\Xœ˜Í&Åô§„9äqK±}+D.{”)ú¯Ò¥
Èµi—„dÁ¤Ø¾•6Àüã†ØU&hªl_J6/¥HalñJ"=Å4ì>r:)æÚÆÀãw¹JLo4¡XëN1È§loJ¤ÍcQØø3Ï>‡ò¥×ùT$äò?*]ê{~uóÜ§ëî‰*¸)***""\r" R"***(ŒSÖQ•G¯ëJ.&r£¡gÎÏqJ$>•]H8ÆiáˆéRâŒ$N<ÓÃõ cÛ"œEdâfé²C Ï4»Ç~*-ãĞÓƒŒvüh²3t™"Éü!©ÂCEBH<€?
z‘´œQ›¦Çjr¶îÕG¨ àÔ¸™º%ÀäS‹ûT#9Éı)Şbú‡'IŞi|ÃE08'µD:H™$éK¹}j}?Zp'8+øÔ¸™º(™“OªaŒrIéPâe*l˜8ïÅ.õõ¨„œdŠ7CQÊgìÉw¯­9_ıjÀÒŒgš|—¤‰¼ÁŠPùíQ©'éNSƒÀ¨å3t»†5>6^Æ¢¥CŒñùT¸™ºE‚çš@ÙäQÒ‚	É•fâfé¢]ùö¥Ü¿Ş¦dzÑŒñSÈgìÇÉÆM81 ŸÊ˜«ÎÀ¥ÚAÊŸÎ¥ÃR$‰‡½9\ŒœT@ç±§®yÛúÒå3•?!CƒÉâ•d€E3?vœ¡zcó¡Å:CÃ¶zR†™€HÍ.vŒñøÒå3•!ãÔğ8â¢è)***""\r" R"***(<9ÇJ\¦N“$ŞŞ´âıÀÈõ¨Ñ‰ê)Ùò?*—C¦=Xu—yôÀ œñøSªZ3t®Ço>”,qÍ R{Q°úŠ—ÉöCÁ#½89E1PƒK´÷SR×A:H™Í¹á© ã°¥;¨ü©$fé\77\äSÁÈäR)‘KPC¦…@ëJÔ*2M.Áêjt#Ù!T¤TÈ@¨vŸCRqšmé’ïoZPçÆ›GNÕ!Ó½}iAdTdäÒ¯Qµ<¤¸è>€HéH‚)jZ3tÇ‚OQŠz•’:
p9ìi4Œİ1ÌA<RQHKÜRåF|‚Ó×•à‘LêE8 T´C‹¼ÓÕÉ4ªêk6‘.Û°ìÔ&{R”SPÑœ 4¹ÿ !Fö<şTíƒÔĞ‘Eˆä' ‘O]§Œ~´Šyà ŠD¸
`*JbîÏğõı('’¨4*•êik=‰”›©¥Q‚z
ÜXzzF @G9¥
È§¥ˆq¸õcéš‘ <šÈ©•qÓ5‡0¢ÈJnÒ)***""\r" R"***(fßc7 84à¡y  ŒÓ‚Põ-ÄÎiTy £şµ*Œ‡ñ©°œa{T‹·-5Ôr21PØrh%¸>†‡ÅCv!Ã@\ƒ´ìnĞ¿v¨ÍKfN6SOğ9¥Ø)zT·byG§çNØ(TçŠ—ĞT6g(²0 ª89§m” äJè‡Pš~ÁêiqƒƒOÁô5v°"ƒÇµ;búSFàréNœäT´ÅaiÊ ŒšE9T=ê["QB æ¨É¥òÁéšP¤`ÖmêdãvOlşTğp çò¡~í< #5˜8€@FjD iªLT
ô¥ÜÆHiA‚E4©#5>Áêi6zjD$ˆ<¯cNHÈ=*_,zÑ±}kE$W(ÍƒÔÑ°zš“`õ4Ö\tI…˜ÑÏ4² Î*LĞPWÔV‘f‘‰Å>´»©§2x`úÑ;Ê7bûÓÕm ROJz©¥i16SFÁêiØ>†” #<Õ&4ÆˆÊö4Ï$”!4=1ùV‰•nä;©£bÔ†>;ş4İ­œU&4†lQëFÅ>´í„ŸO¡«¹Vº`õ4äAF¡§F§*Óš)***""\r" R"***(£Å1Ğf¦UÏ\Ò2€qZFLd>X=3@85(‚—ĞÖ‹b¬0 #œÑ±}éø>†€­ÿ ëªLi*PŠhqĞÓ‚’p*“(—"šTMX1çœkF d
´ÊL‡`õ4l¦¤(JiRJÖ,¡»©£bÓ°})***""\r" R"***(*g<ŠÒèh`P½)êu¾X=3J¯@jÓE¦1ãÏAIäŸz—ĞÑƒèjÓ3"sƒK´úT˜>†€„ÑÌ4îÈ¾¢—	êiÆ.z<¯cV¤PPsMeÁÈ©JÈJ¨±§b21I°zš‘¢9àRÛ<ŠÑH¤îFPZ6)õ©<¡èi|¯cV™[ì¦ƒÔÔW±£Êö5¢e'q”SÌ`uÍXîFSwcøP)©pAHPš¸Ü¤ÄTf—`õ4 `bŠÔiÜMƒÔÒ)Áæ—Êö5H´Ä(9")Ï Ô˜>†€§<ƒUrî7`õ4QRycŞ”GÛ‰\«¢-‚ƒÔÔ†.z<¯­5!Y)***""\r" R"***(U)***""\r" R"***(Ö‡ŒÀ4ğ…zKƒèj“ÔiØ‡Êö4y^Æ¦Áô4`ú«°æ±ŒJ‘QvÒ`úrıÚ,Âè6SG•ìiÁI§…8éEÚd0!>Ô ôüª@„ĞTŠ¥&äTrzSÊÂpjÓ+˜E<­:”)'iÛ©ª)Hj€N)***""\r" R"***(8 ¡S#4í§Òš¸s)***""\r" R"***(Ø1Š6SO“×ô¥ò½UØùÈü°zfOz•T0iB’zS6„eáF¡©„|w£Êö4ùƒœƒiô5*œšxN>ïéNòÔt¡=Jçzf¥Oè)
ŒpZhjv"Qƒ÷OÖ€äPçœ‘VŠSbàúÑƒêip})***""\r" R"***(!ues;äéúÓpOAKƒèjÔ™qb:©éH œçiÅªMÏa˜ÏJP=PÓ¶SJ€)Ü¥Q‰°Ó£Š\CJÈ"š¹qª F'?Î•—üéáKt ©ªcö¡âhxÉü*B2@5Hµ6Æ`¢Š—a=GçIä{ÖŠE)‘à”äg"! ä]‡ÔU¦˜sÛšP ˜¥U#©¥y¦56&Áêi@ÀÅâŒĞPZ¨4ì'“MÇ<T›?Ùı(
å!Vš4U,3ĞÓ‚ iû½.Áêi¦Êö¨üü'=@¤Ş3ŠfNzš7…=Åy¾Ìş€•+®3É§‚#|œb9ãö¤à‘‹¦É7Œ8¥§î‘Q†‚1NVSÚ²q2•+’«àriÊàŒÖ¡ÜEıiÀ‚8¨p#Ø’n´Í2•JƒÈüj}™‘2‘Œfœ‚¹¨—i9§‚u¤àc*#·î
PëéùS1şÖ”zC7H™{ÓºSdÓêL¥HPÀuQNW\Ôyoîş´ ½+7éy^Â—x¨Ô‚1šZJ2tPï5iË“÷Oäj ÀœR&=1C‰›¤JÎŠ $qEdâfé
¤§©qLŒSƒô¹Y.Ÿ‘ #E.})***""\r" R"***(GšQ×®(qD{$J­3R+¯·áP¨$qOU#‚sY¸™Ê‘.AéGJn?ØıiqşsSÊŒÁ†yQøSÑ—;±Q€O”nC’)8#7H”¿¥*±=GãQ«R( f¥Å#9Qì9v„~4üĞTcÆiàƒÒ¥¤c*a‘ê(Êç¨ “ÙZBF~e£”ÏÙzÓõ ıi©ÏCNÙ‘ÏZ—7Ià+Šp9Å `b•W=)***""\r" R"***(fdé·¡§åE ÷©)4bàƒ t«Œi(')***""\r" R"***(à‰(¤T9À?…;czT4O³Jƒ×ó¥ÈõĞ§ºş´'¯¹P¹<‡ÑH §4´¬fé¡U°)êsÈıiª Œ÷õ§/y¬äŒİH:tÅ*"‘pG §ƒÔéŠ¸#šxôü©£gqOîh±›¦ÀûÑÏsKƒœx
-s7)AÇ"’ŒdàT´¬féßê)U·v¤E*y§ªîïQddéØr 3ƒš\ÔÓ|¿z]§5-"\È=)***""\r" R"***(Š6Œf™ÇOÆ¥èˆp@ÛÒ–€2p)á9R€ÊpLŒæ—bç¥<&G“!Ób&yÅ<œö¦ù~ôî‡šM"\âœ9 =±N “RC€)***""\r" R"***(9Hc¢!Î)***""\r" R"***(9WiÎjW!ÂÃ•A<qNUÛŞ‘$v§ªîïPîO(*îïKåûÓ‘éAu$¸Ï4´QA>Í <óNUhUR¹Å=WÔqŠŒåLPœu©2ö GÇZ~Æô¨lÅÀN}hÏQùT”uëQî“ìÆ‚s€8x*.xà»NsRô³°ÜÔş”sŞ¤ €zŠ‹¢y¦1ÅJ›{SÎ*@˜¨¨v P‘J«¸g4å]£¬ÛFr¦
óÒ#ãƒúPªÉåS”qPìfà7Ë÷¥
1Ò¨só
pD=x©v'‘‚!ìiŞXìiR2:sO(;ÍÚær—ïúS‘@ıiêƒ??Ë÷©½ŒÜF*v‘K†ÇåO	ƒœÓ”n8Í.c7)***""\r" R"***(H¹õ•9®pje‰M8DCG1$~Pÿ Jz a‘Êånû´å«6úâ5FÑŒÓÂdg4ï/pÈ¢6©1hh@<ÓÕ çÚ/Şœ ô”‘#„cô§ªîÍ„iñÇY¶g(ÙïúQåûÔşJĞaP3K˜Ç”ƒË÷§ÂäŠxU PË¸b­6RƒL…‡pÂ‘W'©¼¿z<¿zÑnZV#òıéÄ)Ş_¿éNTp¸«R*$>_½_½JË¸ç4Åh¤ÙdA0sšz¦FsKåûÓ€ÀÅZb²c|¿zP€uæœ£qÆi|¿zÒ,P¡@ëÍ<qN ‚‚:Õ]—¸ß/ßô£Ê_ò)ê¥©|¿z¥tRDO…¦y~õ`¡ìiŒ¹ã5¬dPÄŒÍ;Ë¡ı)Uvœæ–´½ÀnÁŠk¦8üª`„õâ=i¦€) ş” ÅNÑàõÅ œf­JåXb¨Ç"”('EL#ÀÇJ<¿zÒáb1iV<öëR,y÷©,ûÕ¦ZW"1àu¨İ~X«-n”ß%kK¢¹JÊ€œ`~T­ÆXòV%jÔ†´*yxïG—ïVü•¤x€µ4Zh¯€:
rÇOÎ¤òıèòıëNfCp=*ÆíùS”mÍ9WpÎh»†yCÛò¦4c<ŸË÷£Ë÷ªNãJå/Ş”(ÇJ”ŒQT®;)***""\r" R"***(ò—üŠa@OTÁIè)|¿zÑ;)***""\r" R"***(+Áç4†¿¥XòıéyÎjÔŠD;0i<¿z—fÖÏéC)***""\r" R"***(Ã­›4L‹Ëÿ j€uj“Ë÷£Ë÷ı+HÈ¯B&©›=ÿ J´bÿ gõ¦ù~õ²jÃZ•ü¿zUŸZŸË÷ GÎ3V™vD)***""\r" R"***(ŒPÏ5hB;Ñä­R˜-qÖª­Iä­ :´îÊß•Pöü©ÔUo”?È¤eÚ3š})***""\r" R"***(6ˆéTn8Í<©~)ÍZe&†ù~ôyc¹§ìoJrÆÄŠ¤ìÁ²=ƒÔÑ°zšyˆ¦”"ÕWDsX‹Ë»WÒ¤¤à
x(æb5QŒûT)D'¯Zx¶iÜ.0(Œ€ôüªa	î)|•¥tÖ+r1F¥Y0ŒqL1ÔÕ))***""\r" R"***(H‰Tä8§àz
‘gßÖåûÖœÃæ!À*¨=éRù~ôy~ôÔ†¦7 tSÕJóKT™\Ìj¨#$ĞœÔŠƒ0¥Ø¾”s™ãµ(C(M¸¹† 08§ˆÔâ”D{ŒÔ ëÍ;´>b9¦˜¶MNPv4Î85JCR± ¥U^˜ëRmaÔR„ÈÎkX´ÇÌGåûĞÉ‘€IåûĞPœÕİ™‘*ÓùSğ=*®{Ò„æÍ#67ĞQè)Ş_½_½R¹|ãp=w© ÀÅBçcƒüTà€uæ–”GÀù¿JÑ0Sb*	R²±ş.{SÏLU§¡¤jX€*ç‘Í;`õ4òœpióL¿h4 ¸‚³ı¯Ò/Ş©>å*ˆn £h=ô§y~ôà è*Ó7Ğ‹Óô¤uôZ›fáÒ“ÉjÑ;Ú…Ôàã5'’Ô¢6¦äZª0)# RGµLM.Åô¦¤W´¹Q×­=IÎ:Sü¬ÿ ëOüÕ©œüíb½‡åHH˜3úRoÿ ¦†²ä?¨=ƒ}	U”´ğÈ*¸`Oæc­K††r X‡¢ş´#­AæsÀ 9ÏÌßJÍÓ3tAãş*p‘Hªªç59\¦¡Ó!Ğ,îR9¥¸58Çzpq¸©p2•pãšpÇZ€9ìiÀäf§ÉÑ&ÜÃ½=w_-×­=‡QúPàC¢ZB™ÎZqlÒæ{V2†¦2¢K¸{ô 05qÜRîRp1š—eaĞ“ŠS³°¨A4g×ô©ä±”©«À©—·Z	³Å??ç71t‹ ƒHX¦¢W'¶h2üÂ²qLÍÑw%Ş¾´õuÇZ„y ‘À4{2}‘avÍ<qÆ*°$ŒÔ±¾?ıu“ƒ!ÒDÁF3Ö¤M‡ÿ ¯Po_Zp8ç5&N™?ÒÔf¢ã~4¹>´¹L;a=¿:>AÎjUb=ı¨pFnš±:²“Ï4àÊ\8ïÅ=7R+77Hœ2÷§FÔ—Ö”;Òä2t‰¿vi@
0B±ı*EëIÅJ‰®rG>µ #Œş5u=éjL%H“ƒÒœ¡OAúÔ9?äS•ñÛò¥ddé2Â:ÓÉ_OÖ BOSN¨q2t®<2’iãnx¨G4àç¸¨q!Ñdê@94íëëPÆÀóÈ§o_Z‡=ºo_Z|}ê Àœ
r’8Í'8.Å1×šO¡¨Æ;ÒŒf£”ÉÓO\íÅFzÓ”ä~u.$:l•TáÇ¨ÆqÉ¢§•ÈLp)ù_îşµ\;ôõ> ŠN$ºhŸrôµüNY àÍ£'H”ô4¡9ëQ‡Jzø©jæ.›C•H94´›©¥$:B®ßâ§ ‡¥2”)***""\r" R"***(ÙÍKFn‚ƒ­9vö<S@ àŒûÒãK#ÙØ‘q·ƒR/APª“óNRàv¬Ş¤ºi’ıN)áA â¢W¯(eÀæ–¤{? ØÅ;³
JìhÔ‡I9JçÍ3iä<RÑ“¦<õçÚœŸxãò¡ğÔ¥A¨v3p¸åbH§‚JT3O  ~›±‰n>JZEÎijLÜB•F[’œŠr83Öœ‰¶•>è¥¨l‡Š6c‘OÏÌqM)èiÕ,ÍÅØ¾”l_JM‡ÔPƒšÍÜ…(P@§.Şæ’•p[7aÈ…]¤ãoëN†è(UÉÀ‘œõ©l‡)***""\r" R"***(X°jU
ÃŞ‡ÔRª•ô¬œˆq¸›zÓ€¥úÎœ*n' UdŠxBG¤'¤U!Gó¨rFn)ØjD\ŠUN2M8 :Vmì*ÅŠRœäS©Û¨¥{KW ÑÉı‹éHšuffÒ ª9¡sÀ4”ä9ÇjWFrHP S‚ç¡¤§ #9-™r¡TÛëRCÒ‘­; tÄJ¢İ)Â0N ¦…ÈÈëRF˜ æ¡³)DU@:Òí_JpLŒæ—aõI˜´‡"¨•* íøÔ@`b¤¬ÌÚSÒ‡ÔS¨ \¨nÃê(	êiÔ“Šwad1“iY©ÌdõÅW°ªŒ‡b%OJ~Åô§ydtÅ/–{šÕM‚C6/¥ÒŸåûÒ…QÚŸ3˜Á=1ùÓZ25•¤]ÂÄ;¨§ŠvÌœšx‹‚µRhCU}êV„rE9cÉÁ©<³ëT¤4ŠáiÕ+GÇ5&9­˜ÓA…#æ4Òƒµ(8§l>¢­6QÃê(sÉ§ùg<š<²:b­1ØTŒAr©^´¤ÔU¦ÊKB-§~êr©<”ñ# 
_,˜«M(?†€µ&Î:óM<V‘‘vB¢ƒÔT¡=j8ûÔÕªÜcZ<ğ)¦ jJGû¦®àE°úŠPƒŠZ*Ó¹I1¥x£aõê)”7aõlã¯4ê*ã&vQFÃê)ÔU§¨)***""\r" R"***(Ø}E'–G¥H‘šBê*Ó°úŠæJ‘š¤ËÏ"—aìiÀĞQZ-n4¦ZiàÔĞı*:kr‚_JO/ŞEh+±»¨£a§QWËƒ¸›)¦,œœTKt¥Ø{šÕ7cB!1Jçš ìhØ}EZwÙA–‡ÔT›¨£aõ¢h¤ÈöQ@Lu©6QNÀô¬Ñ‘‘‘ŠnÃê*R Œ`Rl>¢¯™hc$àš‘!éJ‘œæ¤TÇ5-ê&Æy#üšQ:bŸG>Ÿ­b½†„9äÓ„`ö¥Sª)ÊAè1Wvœ´a¨òGµ>Š9®MØÏ${P##Š}JAv7aîiá4”Sºf8'­:˜7€şTúcæ3Å&Åô¥œS¶QM)***""\r" R"***(Hg–†‹éOØ}E¨«LwC6/¥*Æ?„ÓÖ0OøÓ¼²:bØ¹µÍ.Åô§…#¨—ìŠ|Ãç )UsÉéNÂú~”£ØSNãæPãŠ]‡ÔR¯İ¥¦O;búR„LóO `qKéUÌ
¡Æx4SÊ‚1HƒÎ*‘JcHƒ@UŠyPG Rl>¢µNÅ©$6‚ê)Û¨¡Sš¤ÇÎ†l_Jr¢‘òšv¥. è*®R¨7aÏZ]‹éC6ÓŒRyÕJås1v/¥!OJp$Œ‘EZ¸))***""\r" R"***(Ø}E*.ÑŒÓ‚Ş”¡Ï­n5Q!v¨íJpx¦…qĞÓ«e¢©q6/¥œbœ ¦”Çèi6>q¦ ¼Ò©å[¿4ÚiÜµ!¾YîiUJõ¥¥
[¥Re)ÙŠ‹Ÿ¼)v/¥.uŠ²•F&Åô¥ )B’2)Bòh8*‚9¥Ø¾”åC·ƒNÂŒ~•Iê>qõâœ÷¥Çû"•TŸJÒ%*‡æßÒ“#8Í3û_­'©®F`º$ƒi?áNV^€şul¢œ÷©p%Ò%Êâ´ô¡ŞsNFlõıj\“¢L¥\dšvF3š„1Z]äùT¸#7GB`{Šr°<’3Q+ö¥k7dè²t8=x©Q†ÑÈª¡ÈèsR,‡hÀ•¤û‡­9Y@ã5`zšr³Ÿ©¨ä%ÓDá€<5.óQRî8Á©p2•$Jç‘J=)***""\r" R"***(D	ÏËÈ÷§Ï9¬š2•+“¦0?•=vgüj#OÖ”¹^ÿ fâc*Näè÷  ôª©1Ïj‘eÀäâ¡Âæn‰8aÜ~”„ç£Y	è:U~Çô©å±“¤‰‚88§ª¦2Z¢uÓ•‡CÅK‰•‰TÆE²x™NR=OãYµc'H‘=MH„tÍD¼võÇCøT8«Ê‹&.¤r)***""\r" R"***( Æìö÷¦íôcGÏ‚£•J‘.G­(É8$ÑÊˆöh} ‘Ò€01O 8íéPÓ!Ó°‚OZ‘9ïLÀşí*œg¨¨hÍÓ$¢š¤Ïó§ïJ×3”õ<ÓÕšbıÑNÈ  M.Tc*H2ÙÆqõ§©ÅH0F	Í(â“F¦JŠz}D­ÏËRdúÍ£S¸nö4SA8ƒMIÇ56d:D¨êF3NÈéšŒ *œdÔ¸¤‰tØşõ*5ğ)Êê+6Œİ+–$ÒüÕ>V4¹Ç8ÍG*!Ñ1Ûô§)1\t#àG^)8éX“ƒI…ôÀÇåJ£¾OãRC¦8=éàg¿JOÎ¤©²3öh_“Ş…î(ÙäS‚ sQdC¦ÅTì*E5É8õà)***""\r" R"***(ßdìŒ¥Ğõã¿Jp ÓIùiËœòCØç•1Ê@ê3NOİÅ0)=)ëœr1PÓ±›……§¨ç™ONœÔ8‹•P½)***""\r" R"***(8Ç­5FN)à`b£•™¸\nTu_ÒœFhÀ=Ešfn“¡æ¥,:j0€äÓ¶¶y¢Ä81B‚r:{Ó°AH Qzp
N9¨lÉÁP6€ß¥.Õì?J@¸èM(ô¬İŒÜc‘@9éR 9¨ÕH<Š’?J†ˆp1ßô¢œûÔ¢,ôÍd÷1p‘‘OO—­6 SÕ@Sr b”!#4”õû¢•Ñ”á@Œ{T¨¤g"¡È‡†Ãê)6õ!FÓÏ¬îgÊÄ)8Å8C†•~ğ©6±íRÛ@ĞÕ\sNN¿…9cö§Î8œ™‹@·Jr š…éO@r+6ìg$Æàz
0AR`z
g¢Š—"lÄP0*EhicÓ€ÀÅfÉh)B3ÅXö§Kfn 1MIHTÓô¥'-™8… p)û½(^x.HÍ¦"&MHª…\G4ä EfäfâĞwqüêEŒvıiUA=)ÁBô¬Üµ!Å‰åƒÓ4l=ÍIz]€”¹™”Å^Â¥D8ëHÉ¥T;x5FRC)***""\r" R"***(.Ãê)T0ik4îÌ„
1Ò¤3šhRML£›v%¤2Š—Êö†<rTRæ3v#'ôNG<Ò…àSÕqÉëNãI	°úŠO,úÓè¦>Q›ÔS‚Ú–Š´î£Y2r1FÃê)ÔSNÃ³ç“JÔåR~”¥8â´L,Æàz
P„ŒÑ±½)ã «Sh‡¡=OåN ¢œÖœ@=Eh¤†•ˆ˜db›åŸj˜¨# ¦” ñÒ´R)—ô¥Ø}E=Tç$qNeÈàV‘–…$È|¶Îr(ØŞ¢¤ ¢€	éV¥rÒhfÁëFÃê*B‡°¤ØŞ•²c°Õr¡<”å^9µiÜ¤†”ô4W°§ÑTŠVå‘ÓúP„ŒĞU€Î+hÈ¤a‘ŠZ+[¡ÙAç¥AíKE+´ÊW°ö4l>¢EZl«1»¨£aõêP¤ôIØC6QJ«ÈíéFÆôªM°Lı)|µ4ª4µwe$ÆùIéNäg4T‹Ğ}*ÑV#¯éL’2EKA õ«Œ€®Àã¦ì>¢§hùàf,ÿ tVŠA{ªPË‘€*aÏAG–º*Ó)+l>¢œ±ƒÓõ©?QŠDg5qw(o—†—aõê+UkìnÃê)<¼iô»àMî3`Çó£aõî‡V©”¤7aõí«è)BÍÒ´Lw¸ğ3M!Gj”ò)***""\r" R"***(5S?xUİ	è4œ
zÆ	ëNòÏ÷iUX6H¢è›±<¯aG•ì)ôQt!W°£Ë#¦)ôQp°úŠ6QN¢šbº°úŠ_,c9¥¢¯qs16Jp¸…Lõ©6:Q©B`z
_+ØQ±½)õI´$Æy^€Rì>¢E4ï¹\ÖWo,h'ŸŒœb—Ë?İªR±JCUH94´à´»©ªRd" s‘NÀôBô§' §{‹˜LA@=.Æô£czU«0»cFÃê)6¿ù4ñÓš æ`)Á=OåHºãõ¥AA*@SĞÑ°úŠujÈ®a¢>y  üiÀp)J‘ÔU\jlLAM`£¨ü©Ô„¨ëV™JcUI¥Ø}EŸ¹øÒ®ïâ«[)***""\r" R"***(HiŒ¸ GÏj}qcç‚1ëNXğ8"’€HèkXì>v;aõl>¢…z“ùÓÂ6:S8ÜîŠ]£8œ«¼)Ø•iè
c<¯aJƒ“Nü( ‚†ÑjbÁ¤ò–Ÿ´¼8£?-%'sHÈg””yj:Sö7¥Ò´MÜ|Â„©ü¨ò“Ò”(^”½jõ1¢5)|±´íéJçšjì|ìEŒ€E*¦4à¤@œ
²Ôî‚•Px£czSÀ…Z1ù—“´»˜÷¨w¯­Æx5ëºgöû¢ÉÆÜç94àGsP óNYzT8:$áAş*U]§9¨Uòy?¥=[Œ©¬ÜåE“"ƒÖœ¡q• sÜS„œ`œT8ºD›@§ ~µcØÓƒŒrj%I“\}ìSÔqŠ…_¥80=ñYò3)RdªH=E<T!˜w¥ó9éQÈbè¢À p[?…(8Ïäj/3ÔRï_Z—Mé©«fœ¤õTHAÎ)ë!<ƒ‘Y¸Ê‰eBúÒà{şu
Èp3JÈ¨pFN‘2 =ÏçR¢çïT¹¯oJ‘dÚ¡ÀÍÓ'TSÈ?¥m8ÍD$'iw6zÔ8Ê’¹2ƒğ§(©ü*b9Æ)êùê+9DÊT‰Ö1´`Ò„ù¨•:çÚ¤Yê?JÉÀÉÓDŠ¹jE
rMB¬"µ.n‘7z*=Û¹Íö5“Œ©w%Q“Í=UA¨U‰àƒõ§«Œc-ºD„ÍúR¦îı)èiËœğiXÍÒhx¹§„\sL§)***""\r" R"***(ÇJS9S°¹U¥E5‰ÇŞÍ4`”r£JäëÒ–¢SÆE<8Ç'š–‘œ©!Ôä'ÓÉûÙü)jyQ‹¤Léùß51iû×Ö¡ÄÉÑCÇ_¿OQ“ÍD=)P€qŠ—C¤L)Ê853dO¨q3tÉTJrªù¨·c§àIê1Y¸Ø‡I®äı)N:)¦«níJ:Ô4‰t‡*ñó
‘B`õÇµ8j“¦Ñ  
pLŒî¦)ê)Aî)Yºw$µ?búTJÍõ©Œb¥ÅºC¨ ôëHı}êt2tÇ) óOõâ£§§¨5›‰Œ©±È n´ğêi„“Á¥POAŠ‡I’ 9WpÎj*xlğF+7±ˆâ ı)W à7éM§&Şı{Té"D âMBsŒñN¨{™¸!v±íN1È¦îaŞ9ŒÜåPO)***""\r" R"***(O({ÓT/ğÓ·1ïY»é‚ êiÊ«œô¦SÔ·B?ÎÖ!Á1áç9¡@<
EÚsÍ;­K14*íÏ4õ_îŠ`9aRGJ†Ì]2E]İéÊ6ŒS=)é9Œ™›‚(n­Šp‹<n¡BãšPW 5‘<‚ˆİFëO1È¦† `rœ¼÷¤ö!ÁñÖ É¤^ƒé@ôN(“k”à‡¹¦)***""\r" R"***(H=+3>T0GJ#Àëj€riÜj[dJ «´ç4å hL‚)Á@è+6Ù‹¢€AJªg4”ô$õ¨d¸\†œ ¡z­?ôs'c‘J#dÖ—ĞÓ—îÒnÄòÜfÇíR*d}ÑïNUÏ$SÖ?N+7"\R±ƒÒmñÈà›z-Hy›•Ìd‘V¥8(-9§y|õ§#€)***""\r" R"***(Cw1i)***""\r" R"***(T%°E<D4ª§ïS°OAPÙ)***""\r" R"***(!ÑÅíÚœ!=Å,_ÒŸYİ™5pX”ƒ@‹œí§GŞJærB,YÆiDl8”ùR‚äÿ õª[1jìF9»Ò”g¹§…R:T^Æn6±ş2FI¦t©“'¡¡Êæn,B¬;RÁ©ÈÁ¤Ø¾”¹‰ä#
 ä
z®y4»Ò€ TÅÊÅÀô`z
(¦‡`¢ÓŒ|iaÒ·?xæ©;2’#Ø¾”Pr=—H“ŒU¦Ô“Ndg¥ôû¢b­ Ï+ıŸÖ”B=1O¢©I‹•¨Î Ç­+ %.¡­T´"ÃF"¡Ï#õ©9â‚¤¸¶RŠ±})8ùE;8£#ßò­ã°¬ÈÌdõZQ?4d‘ZD¥”E&Æô§GZ+R†loJpAE.	è)p})***""\r" R"***(Rlí_J6/¥;ašJÕlRI€Rz
pBzñH	)ç¡­"Á¢6@4›ÒƒèhÁô5©7bÁäÖBÒ¨;ºSê”‡vGågøZ_%iô OJ¤;Èg’´¦2;Óö7¥z»¡¦Èˆ#­(ò)å2rV€¤tSVš);sÍ8E‘œfƒèiË÷iİÆy_ìş´»v§ÑT˜ÄØ¾”¦,»J¼SÈÈÅh…ur‡<Q±½*B¤9£ĞÕ–¬Æ=Í&Æô©0})***""\r" R"***(>†­fFc'ªÒ³ÕjBê(­ÁqY#šO+ıŸÖ¤ ”»Ò«™”È¼¯öZULq)äc­I±Œhò=}©<¯öZ™TÉ»Ò¶R‡¿ ˆ Â¤X€­< :
®dDí@B¦*QHÊä
¥!shE±½(ØÔú ÏJjDó1›ÒéRloJPƒ©§tÌbf§p9æ (ô¦'"?+ıŸÖ+ıŸÖ¥Áô4`ú¤Ò'˜‹Êÿ gõ¥§z“kÔ`ú¤ÅÌ3ËÇzp¥
IçŠpŒcîÕ)@„õ§y_ìş´¡IëÅIƒèj®Kd^Wû?­Wû?­KƒèhÁô4™‘¬\ğ)|¼w§`¢ŠÌÄX¹õ¥ò¿ÙıiT€y§‚CV¶3#ò½¿ZQ>ŠcæC67¥y§Ó†ÌsM1İX²3ŒûÒˆÈè¿­H1:QV…ÌÆ„'¯»Ò–Ÿ±}+DK™Åô ¢‘Å8©•VCæ±â”)?xşêƒZE)***""\r" R"***(Hcm
Cn«Ne p(@AäU¢”´Oï
]‹éO@QNëVö"Ø¾”…x5!AÚ“czU+)***""\r" R"***(Tc|õ§ˆF9 )'SÀÀÅZv)MòñŞœªOŠURi¦Ù\Ã„Y=h0‘Í8 zœSÈÈÁ¦ÊNäÒ•UÉ.Åô£búSÆ($â—c
pP@¥ªˆsØfÆô§$dõå]İéB‘ÑªÓH~ĞLFhòıéØ#¨¢©6ÇÎÄXò3ŒÓ¼‘Şœ?Z¤ÌhŒ€JDô4ìJ\CVìAî)ŞWûTáĞQT´)T?.óëI‘ĞùÔm&O?¥Æ{×Òrè¤J	)***""\r" R"***((sŞ¢ÜOFıhƒÃ~µn‘:É:S„„÷ÏÒ W¤Aß5“‰Œ©«À9©=üj°Îx©à`šÍÁ³RÔ~ßö…9sĞˆ¶¥"§Ù£7M(9â3Ş E<9=ÿ 
—ÊœGîçïÎœª*Ulpj]$ON'%³éQ	qOĞÔ8J‘%*‘¸qQ†lõ§©ÁÉ›“¤É—>¢ïQ¡Ï#õ§r@ëß5›¦c*]É³Æ*D#¦Z„gÿ ÔiêÁª\,dé“ ldx÷-¿•0O›‚1•"e#qÍ=9<Uq'§5,n VR‰“¦MÜ~TàHê
„y'ğ§†éÏëYr3'Mqù.{şu
¿cOéY¸ØÉÓ%+ÎqN
äñQäçó§,„T8ØÍÀ”.M(úô¦y¾â—ÌÈâ³pD:i'4å8ë‘Å1[<b¤qÉüêlféØpf)üö¨€iÁˆ¬Ú2p¸ğ23‘NUy'zp8©³0t™"¯GâiáF=j0r8§n$`Ô´féÀô¢š£#ïÎRC¤˜äèx§Œ“Œ~”Ğ»zÒ)***""\r" R"***(Mµ2•ûr	§ ;ºÔa›<xÏz–ŒKäçuIF
>iŞcz
‡gì‰Bç©…(P*5byéR)¡?dÕ„éGJp`FzSBç¡£aõ¹Q›¤î<b Á8¨†TóR!8Ç)***""\r" R"***(XÊT‰U@ Rí'¡4‰÷E.HèjyLıŠÔÓÂ°04Àş´õã¾>”œY˜ã“À?£hÎE#dr@¦‚szÔXÂT‰Tdâ*ş´àüğjL"P	8ª¥MF‡	§dôÍK†N‘*€zšpPê0¸ã­Hª"±’1p° Ò•FN))ÈZÉ¢$EP PF)***""\r" R"***(FŠ>õJŸv²hÊPB=ˆÇÒœã¥ éHÁÀE\p*B Œ`PŠAÅ<Æ;VrdJaH9§€	Á F{ÓŠzÖMØÍÃPÚ½@ ("€ t&œ ƒPÙ. ¹'Œ~5"¨=iª˜ù…>>õ)***""\r" R"***(ÜÊTĞà3Ü
\•à`ÒŒÒ…'‘Y´c*i‘ÈÅ93»¥5AÔŠF8üªZV3tÇ¨FE( r(P@Á§ª^k6C€¨Ê¤
¥4)ùÓÁ¡¨2•4.ßF ôïN*3‘J'³½Œ\T‘öÏëMT ç4åÃf¡»™Ê#À är¯<Šh\t5(éYËC')***""\r" R"***(DòÁè)ÛH8¥BriÃäÊRv%¡?ò*DÈŠD Oz‘S#&³ÔÊQ¸Š¹=8§¬c?ãB¯aOQŠ—s7Ù§8Çó¤© úTâ(RÔ¢6$QÓË’1Rô0’@<€)V6ÎqšE'#õ"œf³lT<Œà
J}“3œP‹’*EŒ“Í*‚ÃŠrw©lÁÅ Œ¿¥Y?vONŸC3”uˆÀ`ŠzÇßìfœŸtVnFN#yşP‡¦?:“¡qéSÌC£D\t5"¡
)â0zrÇéúÔ¶fÕÄò½W±©r=hÈõ\Äy^Æ+ØÔ¹¢€sÒšZä^W±£Êö5-\Ì\¨Œ!^€Ó•sÂGZ¥&Ø%a6/¥X=3O	ëNÆ;U&ÊI²!=ãN(@ÿ 
x8¥Ø}Eh¼ÇÊÈğ})***""\r" R"***((@FjM‡ÔR…©XVc/oÎ—i¤
OJq@j“‰ŒcŠk!<b¦d dSkX»DB,ö4y^Æ¦Q“ŠVPEl˜5b+ØÑå{–ŠÒ2ÙÂÀäRy^Æ¥¢µæB 4¡I8Å>”)'ªMÜ-r2„
C‡…JT“IV¤B/+ØÓ‚ÿ ×§€IÀ§l¬dÇvDTŠJ˜Æ1M0æ·Rˆè©>ÎGZU‹ŸÎšhi"<CJ€ƒÈíRô4Ş•¢±i\(Á=8'©¥
¥1)***""\r" R"***(Áô4`ú}Ó°
IÆ)|¦<âOOº*À‹ÊJQjZ*“Øß-!R*TàMn‡éZEjˆè¢•>ğ­(6œg`ú}iØÊê)***""\r" R"***('•ìjZ*Óv›Z0})***""\r" R"***(>ŠiØz22™9*i~Æ¥ ’(ªOP¸Å‰ñÅ=bõıié÷E9 '‘WÌÁ±¢.:U‹Ûó©)B“Ò´R'™4\ôü©\t?JT©æŠ|È9‘·$ô¤òJœóV)§ãT™7d8>†ŒCO£«¸®5W=sNUÇLÑN½>`iô¥;Ó‡'ƒŠwlM‰°Qåıiié÷ER3nÃc 4¸>†ŸE4ìl@ v§"’”¹#i…Ğ”QEZi‚iˆ@#‘“ŒÓ¨«HMØf¡§"‘šxQŒ±¥GCT'!zŸÊ®>ŠjÂR°Ğ¦•cæ©¸dƒNoI!9ÜaBøPÔú+D¹†ì´ğ¤Ó•F3ŠpRzSˆÊ‘Úšcï‚*b84˜Ï©1)‘l¦§¡©Z1š jÖåsí#ŒQƒèjm‚ƒÔÕ]˜PŒÿ JxLiè ÓÂè5 R!)èhòØô©¼z6JW+œT¨Æ?JpqÊŒÔ4¾X=3VŠL‡ÉõÅ23Sy^ÆƒsT™\Ã/oÎ°úŠxRzS¶SL9ìE°úŠ<§ô©B sKM0öŒ„DÙäRù^Æ¥¢ª÷hÆ*àÔ»ÖERÜ= 0W±§€@ÈıhŞ{ŠÑ\¯h"Æ@ãõ¥òÚ”FE(œ
´ÊU )Q‚(§ìÈäš0O­hĞnÃê)Â0zf# c4å¸?™ \çå]Ã'=qFIàŸÂ¾ÅÀÿ H]ààæ	=¿Zˆpqœ{SÃ‘ÅfàŒåE)ÁÍ<×5 r)Ë&¥C„¨³Ú¤Ç"«¬¸=qR‡àk9@ÂTI)Ê[ëQ	28§,¤¨äf‰(àõ§*©¨ÄœtÍ`ïQÈdè’lç â”p*0çÖ¤Ø5&N•É7iş[Ãğ¦#O2Æk9AèŠ»‡PGáO “Qù­œ)***""\r" R"***(89Ï'ô¬ÜL¥E Àp
pÍEæÎiÊç®r)***""\r" R"***(C‹Fr¢‰U› æ¤½Bzz1ÈúVmJ‘:†QÀ§TK.;âœ$'k7	QcÇÖ½:ÔJÌzÆÿ z³p1tI#½9K¢£ÔåoSY¸™º,#ğ©Qj®ğsR$œVNÅÑ,?ZNEF%À?¥.öõ¨å3t™ -´õğj$~ıéêû+79R%
GzU<
vÎô±ËÏZÉÀÉÒd	ëÅ=PãƒŸ­1eüièäô¬Ü,Œ!ÁHê¿­8Â£$M(b:ÍÅ“ìI—§Zr©<Š‰ã9â§#5¦r¤J8šrJˆ1îÕ"Èq“Ï½K‘2ÅÙ¥(ã¥1dÏz“{zÔ8³QbùåiŞ_½ vÍ80<T´dè‚¡Ïğ§ªüÂ“=OJ@HéSfg*Dª¹ïÒŸP«18ÆjHÉìj\Lİ6J«ô´{Š+>]Lœª»†sJ Òg¹=I ş4œLåLr–Ç”î´)$dÒÔY8
ƒ=ê`ƒ¿5†ªHşµ-X‡LyF©c9ÛNf=
ş´ŠHè{ô¨hÉÑ¸¢>}}©Â<… g¸§)è7~¨fNzr¡Ï–œ ¾œVlÊT…D=ªUNÑQŠ“>¢²’9åH)B“È' ¥}qY;ìe*B 8Æ*EP9#š`$w§«gƒY´Ì¥LzMH#9¨ĞóÖ¥RHäVrF“¹")äOòıéŠÛ½©I'šÆQ%Ó£zP“ŒSCs‚0iÁˆã5›L‡HQ|Ó•<R¬™ â—;øéY3'Uvœæœ«»½4)êEmİªL¥L`FsND\R§zz®áœÔ=ÌÜT8â‰£šm©îÔ39E Í<&Fs@LŒæœ+&îbà vœ†x¤UÏz•;Ô6g(h0r)***""\r" R"***(8rqN	ƒœÓ±+7.Æ.BóNTğ)Ta°iõ›fr€Š¸9Í9FãŒÒ§_Âœ' T6e( To¯Ög="w©#ïY½Œ¥awæ¨ØùM*®áœÓ•qÀ¬Û±“€±©#Tà
E‘~íK‘›€‹#ŠrÃê)U°iêÄõ›“1qNÓÌ,)ÊØëO©m˜Ê,‡Ëõ&œ±ëR“Šw—ïPîÌÜF™õ§,}ñŠpR;ñJ=*Ñ‹WiÎiá	ëÅ8g)Ñ÷¬Û¹ƒˆÔŞœ#ç­:?Í²F„# ¥“NÁÆ{T‘v¨lÊQg¦)â 9§Ô‹Ğ}+&ÌÚ#U$`”ñ4µ%#)EÀ8ÅKTş_½cBš"ÌƒÉjQî*B84dãJZˆ„ÇÏZ<¿zšŠÓ˜vdh„t§¬g"–œ„œäÕ	¡ ÒŠ’ŠjB²CUäÓ‚àp8¢Š¥1…(ô©×ğ©dg5j@1cÏ½<J–Š¤À„ =(òıêj+XÈ‹²‡±¤ØŞ•=²•‚äz_/Ş¤“µÈëÍZZä~YëŸÒ/Ş¦¢µRb e`}© $àT¯÷%j›±ka…Hê)*J '¥h˜Y)***""\r" R"***(òıéØ'¥;Ë÷§V‘ĞI"0àÑSÀÎiµ¢eÑ°°éRR“Š¤ÂÄ>zÑåûÔì»FsIZ)XiØ#<àÒìoJ}ù®'¨ÍéFÆô©¶Œbœ§pÎ*ù…dDã“G—ïSQT˜È|¿zp©(­^ÃP`\T±÷§Vˆµ±XÂÔ_½Yºi•hd!0sšu=†áŒÒy~õI’İ˜Ú)ŞYëŸÒ•Woz´Ğs)***""\r" R"***(O^)|¿z’>ôêwaÌÈŠÔ‚,œf¦¢šm‹™‘ˆHêE9c­:ŠÑ^ávÃ¥<(y¥^ƒéEUìJwP‘Å0F§R…-Ò©6ˆÂIÈ"ÀŞµ`&sCôüj“dÜ¯äµ(‹îÔ”UsÙ’Ô¦jtg"–­IØ.Êë(Å8!îjjcıãO˜–Æy~ôy~ôêzıÚ¤År//Şœ%iÜ‘ö £Õ=)***""\r" R"***(Ğı*“¹¦ù~õ5´vv"Tô4íéO§'_Â˜¹™BO4¾_½MEZØ‡$3ËÚ8Å%<‚{Òy~õi‹˜Tû¢–‘FÑŒÒ“M.¤9!Á23š<¿zUZbæ y¥ ” ĞSêÒß/ŞƒGZuÉçdF)DLjJ)¦R“±½({ÓéC‘U©\ìhAŞœ±cÚ—ÌöıiÈãœsL|ãDyã4¾KTŠwâ–­!s²1Æ¥XøëŠx$ŠpsÜU¦ÊU—ïJ"'¡§ùÔàr3T?hGå³GÔT”+B•K‘ÑOØAHô |è@„óKåûÓ€Å*ÇªIêj7`õ4†1ØÔ_½_½PÔÆ,Yíš_+ıŸÖ¤ ”U¦ÃÚ"1<Ö”D ç4ğ	8õiØ~ÓAŠ„K±½*@¤ŒFÆô­"ÃÚˆÆ1J‰Æ)ÊšQÖ«˜=ª?&ÉçŠ]íõ¦îö4›ı¾ñÄÿ O"@Ù?{¯jz}ê…g4ğÙ8Åfàc*lš•FO¢”ôfÇ¡ÂÆ.›d£#©§+1íšˆ;w¡Çz—™Ê‰0$õªØÅD=)éÈëQÊe*(•\‘œÒ€øâ£V+Çjplğ+9FÆr¡Ø8š‘dnÀşuyà¤rfâe*$èÄÓËyôéP«2õÅ/˜IÈü«7™J‘(“”á)'¿J‡ÌÏğÓ‘9©tÑ‹¥äN¤üiA#¡¨ÃÆ—yÇŞ” béBG­9	=jb;gŠ•X.x¬\Œ¨“( sOAß
ÉœÓÄƒÔŠÉÅ™:)***""\r" R"***(“ OJz†íÖ IïR$£Nk7PdË¿7ZPHäT^nŠ¼Ô8\ÅÑ‘ #T©˜¨îŒT£æ³q±“¤HÉ§*°šon(úb¡ÄÆT	Up)Ã‘ÈÅD­“‚iÀàæ³”LİäƒÅ9O</ëQù‡Ò!'€k‰öœ”õfÕlzÿ :”zŒVmJˆííëBœ¶I¤£µ.72tìLü5 b?Z…àzœŒÖR‰Œ©;ŠzdŒƒŠb¯sOzƒY¸™¸§qŸ¥JúT+•şªZ2tÉ)Up*5'¦iõ6d:cÆO$bœ£qÆi‰»×Šx8êü*¹“¦‡õ4øéèiêëƒøT4C¤J¼vÇãKLR@éšrí<Œ~U›‰‹¦9AûÀSÔÔb‘GGáNõÉÒ
	üè¦†îsõ§G?Ò§”ÅÒ±"ôJUlqŠj’G"œ	‚*Zd:céÊ`9íŠzî=ø¬Ş†R¦8N=GÊ)A<O²z£9Sºœ‡œS@4ª§<ñøVm\ÉÓ$ EHED¬ËÔÓÕ²:TIJÇícÉ4àsLV9Å?‘Ò±’ÔÅÓv&FsNQ´b‘_Œ0§ÆF*¹Œ©
§i©ñœâ£'´ñÓ­CHÅÀ•CcÆ”§uü©ƒ+Õ;23ïXÈÍÓb’OÊF3OŒ`QÙä~b¤†éYI¸2dç4êbN0iØ‚±hÉÓ£qÆjP„õ¦"ç¥N˜ç5›!Á BzñG—ïOU'9â—aõÁÃQ ÷¹§®1Å
¸ RÔÈÍÀpLŒæœ)ª§SÍ8•“1påûÔ¨pj5T£y9³w3äúRÑš'›¿R%MMß…HŠsœSQORF ÆLÁÀU3NT+Í. è)ÉéPÙŒ¢ƒË´ğ¤ô©Ş¥TŒÊ³lÅÄWh©#Œb—ĞSdæ³z˜J,UzGß…é·ñ§ªdb³ÖæN- À`
rÇÔèÀèEIå‘Ó<ÆrˆÕ‹>ôà¬Jx°¥ÃÓô©r2hCE8!Ï8§ˆò3Y¶fâ1c,3ı)Á6óİiê¸Å9W')***""\r" R"***(PİÌ¤˜Äv§ìoJUBJ‘÷‡éRÙƒˆ‰i|¿z éšBŒ;VnZ™I4Ää^šU­€Vm™8ÜpV=©ê	ÇjEäiè¤r}+6ÌåÀp8FIæ”Ô
‘Pj\¬gÊÆGZ*B½ˆ¦”ô57LQ¤db›åûÓü³íJ#ÁÉ®,\¤~_½_½K…ô¸‚­7qù~ôª¥y©„C¸¥ò×­S´!¥UÜ3šyLéF è*‰²M8/`)B3NQEÂÉ#ã“N})à:
¤Äâ4)=!u©0AJc8ÉÅZV"¢¤Àô`z
Ñ;d0)# R{T”`zVŠW"<sš*LAF ­#&Æ0FqIRQè+tCÜˆ¦NsHMMè(Àô«‹Æ,|zRù~ôáÈ¢µL°¡Iè)À)pAZEu¢¤ ƒMØ}EhinÍ?aõ«êE4ìB//Ş‚§ëSm”`z
|Ä6ÈB×Š
Õ)°»1Ô~•jL¥v@A§( sOdÉÈ•W+U"•¯¨23š<¿zu(BFjÔ‡dÆªí9Í-;aõ\Œâ©H,„
OAJS­8)ì¿¥)Bx­SÌˆ€x4ÒœğjlAF ªæ²N§,L§5 Lôï/Şš9=é|¿zÆ{Mê*Ô“0Ï/Ş/Ş¥1qĞÒl>¢´æ%²?/Ş€ƒ¹©6QJÈÔ…v3ãT»ñG•ì*®Éº#9¥X³Û5"®:â”AV›CLo—ïACØÓÊ3Å%h˜®3czR21Ô«÷©\t«Nâr+ù~ôª»NsRàz
0=U‘<Ã“ĞR„=Î)á	íŠpÃúS½‰æ"òıèòıêj0=4Ğsù~ôy~õ6 £ĞV©‚d>_½8T˜‚ u_Ò©k¸]20¤y©0AA õBm‘œö4Ò™9&¦ ¢ŒAZ)36Ùˆ†œ±2œÔsĞS¶QNì—"5R"NØ}E*¨j“¹/V2Š”GŸáy^ÂµDİP=Kå{
<²:bØ]	ëNÈ»Aè¿¥R±›dt¡Iè*O+ØQå‘Ó¢0”T˜‚“éúU]‹™Œ¢Ÿ…ôı(+Ç Q¸Ô†QNØ}¨Ø}E	 æJ#9Éâ—czÒ®ïâ5cæ°(Ú1šZPÀš]Ãû•h9ØOu§ª68)'·áORHæªì\÷±½)|¿zx`6Šp ŒàU'pRhˆGÏZyV©Üß¥.)Şãö–ÜŠ('¢,ô…¸ı¤HÀÉÅ/—ïRy%zÊ‚ƒ±­U‡Îˆü¿z<¿z~Ãê)Áaš½¹Æ,J{Rù+R¢pŸ;aşà ŸhB"¡ GÎ3øT»Ù AV˜{B=¥GJ*P…†x£ÊöZªDŒz
rÅÙ§ydtÅ(OZ±:ˆü‘Éõ4 úşu›œf”;
ıÓ?ÕùPd«‚pøÓ— ñÍD²±8ş´ñ!:ÍÀÉĞ%»âœ­·­D%>£ñ§£ŸAQÈdèù)'¸?Jr®zÓAŞ¤ß‘RãcPF:ş•"ãŒ8#Ó•ˆ”¢fè±ôå˜4ğÜ{Ön&nˆõfÿ :xcÔŒFI¥)***""\r" R"***(ÕŸ!Œ¨²U%‡4âqŠ9ëÅH&ç­g(Jˆ¡Nzz¯lştÑ&zş”àØ9¬Úfn“)***""\r" R"***(8ÇéLzŠr¸Ï›‹3•Tã=©ø' ?…1\ãŠ|rzŠÍÄÅĞ$U8éù
P¬yÇçH²)wÂ³”nbéj=AÇOÊœªAÍ1d8ëŠw˜Ş•‹‹!Òd‹×¨üiË‘ÓÒ¢Á§†#¡¬Ü]Ì%E#;T‘’MA‘ÔTñ:ÎQ0•\ŸJ)¥ùãõ£y=qYØÉĞõ$ŒŸÒ£;S‘ÀàÖrFnú‘#€:S€9§£ Vm3S¶ÃÕJÔˆ­¹¨Ãx©Uúâ²qÔÊTÛ‡ıéÃ¯OÊ“9ëùS— coåKÂT‡*gÿ ­R,dñ¨ÑöñéR	}Åg(Ê“2*E9* üò)êä{Š‡Œ$J÷j!Ï5Ê¤Àõ¬ÜL;Ú=)Tò)¨ıÈïOŞ=)***""\r" R"***(CFNN8&8¦«¢	=jLİ!BóÀ§¢‘šD‘Ú¤½CHÍÓĞQ´‹úR«cƒNw"±qÔÍÒ	ÔõÉ÷¤ ¢œª@ùE'g*v?•/ÒœsJš†‘“¦˜å9)è¤ç+úS@ÀÅJ;â¡™ºB”ô§9Æ?J3JµŒŒİ1Ê¤zRÒCKÓŸ×5›LÅÒç1NROR)›‰îiêÇjÍØÍÓC‚–àTaŠbw©ñÖ³hç•;	‚§šx ŒŠO½È4p=«)DÍÓ¸«ÉÀ§…Çø
j©'=©êÍĞ~µ“V1•!È¸æ¤P1Óó¦ÇUüê@F:ŠÍİ™JŠ©¹§í'ŒP¬3ÇãRsÚ²wf.†„9§ç…Çá@<ãJŠx'šÊF2¥a:d~5 ‹¿ó¥\ƒR ÅbÌ\Hùàö©UqŠE^Ê*U+ü_…fÌ%Lÿ ×¥Ø}E:ŠÎZ:m«ØŠ]‡ºş”å+G4àG^µ›¹‹€ÕŒĞÓÄd 3J»{jENrk2X‰ iéiT2ô}êD O^Õ)***""\r" R"***(³@i‹ØÒìçîş•%(#¸¬›lÆQcU?J‘8ãšàTˆÅc-Ì\Aæœª	ÀÅ* O5"(Î1PÚ0”AS=J«‘È¦ª‘÷EJÆáY³'¡@§*dqIOŒg ¬ŞÆ2¦,cTª„ŒŠ#C‘ÅH‘šÍ³>Aâ¥p9¡x#µ<qY·c)A\ç•¤ÚEı(E#îö§œº+&a(XfÏöJ_,öÅ>•@=qS©Œ¢Ä=i|¾r1O• 'š‡sDj©&¤UÇZ6¯¥9 läT¶fâ
 ç4å@"WƒK±}+&Ì¥›8ÈZdıßÒ ëR"†Š†ìdà1`Èâ‘ùw©§4õR"¡ÈÎQ#ãò©£CÏ4à£ â¤TÀä}+&Ì\Hš1Ú¨ôı*}‹éMh²x¦ŒÚ"Eı)L9ô©0(STU©f@a phXØGéV6/¥Ò­HD!XöüèØ}EM±}(ÚÆ8ô«R™–}¨ò½…Mµ}(Ø¾•\Ä¸ùgÚ—aõ.Õ¨Ú¾”Ó%«l>¢œÆ?búR€AVÄ4FO_ÒœG¨©  ¤eµhÄÕÈÊƒÚ¡ÏTH¤ªOQr¡»¨¤Ø}E>ŠÑ0å°úŠ<¶=)ê<ÓÀ ­bì¬ˆ!_¼(Âú
”€zÓY~Q[©"u#(Iãl>¢Ÿ±½)Ê£jÔµ¨‡Ë>Ô¢2zş•.Åô (j¤PÑÇZpŒvÍHp8¥
AV¤Ø•ªş”`z
‘£îGëIµ{­>f+ŒÀô' §í_J0 £™ŠéòóéG•ì)ôª<Õ)ÈÊö¢2zş•0Œ‚œ‰‚>•jCZíKöqíSì_J6/¥Z˜6AöqíM0°8gbúS\V‘˜“¹ˆ÷œ#8ëR†\r¿¥.Õ<â´Rr-‡ÔPcôıjPª@ ¨9âµŒ¬.b+ØQå{
“czQ±½*ùƒ™òø÷£aõ CG»Òšbnä[¨¥UÇ\T›Ò”FE«R%»ØŞ¢ 
—czR2âjDÜĞQ´wô§ì_JQpµi‡3@Ç"—ĞS‚r9¥Ø¾•¢bè(
{-<*@©¨9´Nà@T÷`z
œÇœü¦˜a=Ö­Xğ=(
[µKäjUŒÍUÅtEå{
<®sSl_J6/¥>fMÆ,`ôıiJ‘Ú©ıÑJàgíT™‹ĞR¥I±})¬ 8i²nFTƒÒŒCR')Á9Õ¦W1¡§ ªM‹éFÕôª¸¹†)***""\r" R"***(Ğ

d`/éR¬~¼S¶/¥\AÍ¼§ô¥XqS²Œp9¤ØŞ•i³7!«;Rìÿ gô§®áÁRÕ+ÙÑéJ#Ïğş”íª{S‘Aê+E±-ØA?‡ô£gû?¥Hèÿ UÙ›™ÏöJ6³úT€bŠ¤î.rÈ8§ `-IO
¤t«L\Ì‡a¥Ø}EK±})pAZD—")ı)DG¸5-Dó2gJ#`y-3D{?Ùı(Úzmı*J $àS»'Úìÿ gô¥ä/éRjz®FZ¸{TB!9åJ_$tşU>Ãê)67¥4ì/hDô§¨äTŠ¼r(Ú¾•¢w;è)B˜4àƒ<
xV8§{´"ç¡©<‘ıÓùS¨9#ô©²(L^Ğ„B3÷Jp‹ ©Ö—÷uVhˆü¶ëIå{
””Æ1FäşïéV›°B/+ØS•íšm=ô¥ ‚ªìJ¨À‡Ó»¨©6*ŠBÃ²Ši‰Ô#0’y4±éR¸äS‚©ÅZv´"X¸éùS‚vÛúTƒ `-.G ªæ¸{TGå{
Q=Gä)ùOîÓÂĞSj~=Ó•˜öÏ½3zúÓ‘Æ+õWı…•+lHõ©÷?D®3‘OY9ô¬œ.a*7$Ş¾´å`9¢óKqJ§iÎ+>CEØY‡lS•ÿ ½P¤ƒéõ©QÆ8æ¡ÀÍÒ8ÓÑñÁ\TLàœ
tyƒŞ¡Ó2tÉÓ“‘OÎj$“E<È ¬¥LÆT¯Ğ>1J=)***""\r" R"***(D­:TŠÍéšÉÀÍÑ$RÇ½:˜¬àã9#Ö³q2•!èØÇãOO Ô@ó‘úSÔäf³p1t‡©cŒ=iÆš­Í8ŒÔ:m˜ÊŸrDb;T‰'+P¨ö"¤GÉæ¥ÀÎTI•°84åbO-úTaò9§ t#ğ¬eJŠ¹%97~ÈsR¤œò+)DÊTšÚ8Ïµ8tc”o_Zp|qšÉÁ˜ºC“8æ¦B3œâ¡<†©Uˆè1Y¸J‰!$òhx¦yƒ¾iêøVR„© ç%z¦pIÍ5$†EH®3Á¬œLeIŠ¨3òÖ»‡SC‘Ö”8ïY¸³RdˆGaOS×ÿ ¯Q#Æœ$#ŒÖnR¦Éùù†jMãïéPÏQŠ‘:qRâbé&HFiê¼ò;Sˆè?‘[p¨”L&(–¤QÀÄàş*µ“‰„¨Š‚74'BiÃ­fô1•1ÈGCN¤RHäÒsY5s'D|hZ;ş”ØÏ8ãâqPÓf~Èz:7éRŒÕpiéŞ¡¢"@ä{zÒŒ£)Ïp~”¸÷¬š2t…éÔzSÇ¦)¹ÆÜşøğOJÍ£7I1UO]¹ñÀÆ(¢³jæ.’C•›Ó4ñ„S3OU9Î?:—fà;æu÷£æ}éG«ŒŠÍ£)S# cñ©Í'°§¯Y¸èdé‚FAàÓ¶·¥
Ê~”ş£­s½Ì¥HEş~5"®Şô‰qO\õ¹Œ©ŠŠÉ¥Ø=(=F)@ÏcPÕÌ !Çœ#ã­*ôéN
OAY¸™ºwªGñ}*U#ŠhAjHÆdÑ˜îôÿ ˜qÖ…_îóNÚGjÍ£A
¤c)***""\r" R"***(O² *09åMH¿z²’0•2TÜOµ=wgŠjtæ£ÿ ZÅÄæ!À‘È©=Å1W'œÓÀ?ZÍ£	@•TNhÆ:œP¬GÅ˜™¬¥:` @Í=W8)``R Î¬Ù›¦„TôëSF3Á©1ØS×î¥g#PÔ^”ı«×«Ğ}*EˆÇëX;™8XfÒ)***""\r" R"***(.Ã9.ÁêiU@â³nÆN#=¸©Q1‚)***""\r" R"***((PsN\çŠÆ[˜Ê˜rr4åE(\÷§ 9éÚ³{˜Ê˜ '¡©¼(@&¥L÷/cSHb§÷E>8ÏR?rã<jTë)^ÆR‚°ÔC€)àm S•Tñ})õ‹hÅÃQdÔä õ'µ=#8àâ³lÊP€ƒƒN(E*®s¸S‡5›g<à1F[šxA9Áğ óI´ŒeH9"— Í(ù¸¨§©=éY96a( aÓµ=SûÂ•WŒÚ€ŒäVm™8p4nõ"®s‘OXÆz†Ìdˆ–.:f¤HÈtT›©©"@EdäÌ¤¬1c gğ£Š“`õ4l¦¡İ£«€UÀâ€Ôˆ™æ¤ ê+7±›BÉäŠk Ç¦*qÈ4›©¡H‚éFÆô©¶SFÁV¤KÈv7¥Ò¦Ø=M©­…ËbéNZFLÓŠU©\D;Tv¥ÚXtâŸå×4  0*ÄÕÈü¯öZ_,ã§àÔ İÖš%¦BP”›Ò¦ò½_±­H‡”ı‹éJ±ãÿ ¯JTÕi’1”ÈÂ œ‘R•$r)***""\r" R"***(&Áêj“°"=€ğ:Ò˜ÔÈ‹š~ÁêjÔ™v+(#¨§ OJŸbĞQkE2Z!ØŞ”loJœ :S•A5¬eblŠÛÒ€‡<Õ­ƒÔÑ°zšÖ2‘]bÈÎ3ïKå³úÔû©£`õ5ª‘;v§…OØ=M(Œ¯AV˜˜ÂŒF¤1z/ëR•#µ>†©H›‘y?ìş´y?ìşµ.¡¥OZ|ÈD>Wû?­9ST»©¤òÇ©£™”˜Ğ è(§ì¦–©;”5“HÃ)***""\r" R"***(OÎ)
‚sZFH™£ËİÈ­< 4õ@FkDÉ!ò¿ÙıiB0*mƒÔÑ°zš¾aİ‘”àSv7¥L#Ç8?Z®®C±½)Bò*_,{Ñå{µ!]ì_JFA”T¡6óƒøÑå†<VŠD¹ìoJr3‘R±ØÓ– :š´ìK‘Rz
k£g¥XØ=M©«Œ…ÌVDÏsOG TÛ©£`õ5¬dI Ç"ågøZ~ÁêiÊ§ ­ä^Wû?­?Èlç5*¡¡§„ Õ&È‡czQ±½*m‚ƒÔÕİ…ÈDœ•ıhò¿Ùıj}ƒÔÑ°zš¤ÄîAå³úÑås÷ZŸ`õ4ÖP1Š´Ù.ZˆÈè)L|u§Qõ«[äDÑã§åL1rGëV#ß-kHîĞˆ!FÆô©¶SFÁêjÉ»!Iæ"ã§ëO
"—Ò­X—!¡	ëNò±ü?­<(^”§‘Šµr\ˆ¶/¥Ò¤Ø=M©ª'™‘ì_J6/¥H¨AN*GQT¬'+ì_JZy]Ôy^Æ­åqA4»Ò«‘È¤+ƒVdŞ£v/¥(A8 îiË§çT®K•ˆØ„PJÑ“ÆieOCZ$J›µjP„õ§àúpAZDØÏ+ıŸÖ+ıŸÖ§Ø=MX÷ª9•şÏëG•şÏëSù^Æ”G´n¢âsĞ¯åvÛúÓ–?ÿ UJT´ cŠi\ÍÊä~Wû?­2:
z
w”ç¡«!ÊÄ[ÒéRİzæ#ÔÓAíloJrÄqÊóRª1§… c4ï`ö„!zx‹Ÿ­Iµ½éBÿ ×§qsÜb¡=iŞWû?­Jÿ ^°zšwPƒÊÿ gõ£Êÿ gõ©öSFÁêj”™>ĞƒÊÿ gõ¥‘ĞTÛ ~´İ§ÒµÁí( ò)Ôà õœ«0çI
¶)#<
°«À¢€ö…q!ZP‡<ŠŠwdóÜ‹hÆ)***""\r" R"***(Ò¥Áô¥Áô5Z‡2"
ANUn™Å<)4üÔÕ&ÉuÇ	Ïò¦ç4æp¤Ü;Í~¾ãcı¥tĞªÌÜàSĞóLVNƒùÓĞ¯¾µ(ÊT’NP{gñ¦«.yæzt¬ÜQ“§.>¿…Iœ)”ıÚmíŠÎINš§×J® Á¦|£Ò€yâ²hÆT¢JyõÎ9¨Ñ€ÁúT€äf¡£A!éÖ1ßô¦#Áô§VN&R‚$‡4¸aØÓAP{SÃ’qPâŒ\‡áNRsÁ¤sÔS×fG6FNœG ÉäSÀô!Q8§©Rx“F‚LXĞ}©á@¦‚AÈ§ä†³{™¸«
( t$€ƒŠpeî¿¥fÒ1q1äT€‚‘H#O]¸Ï¨qFr‚sjEáF})ªË@úÓÔŒdŠÆQ1qC„dÿ õªTR?úÔÄ“Ò¦Y§…bÕŒ%!R8Æi *r8È¢“ÌÏV|¦.	V'¨üEH§ b£R1Ú˜Àõ¨”QŒ ‡®îß­?Ş˜Šz°ñÍdÒ2•4*®êg®3MVOJxtYJ(ÂTì(99ÇçR!ÈäS×Ğ~4õeê1Y4c*d‹‚8§¢ŒnÇ4Å`0FµHcÿ ¯Y5s'=:æ¤R;¯éQ, ‘dP+'dà‰cöí¤v¦Ç*Ôñ0Î*L]4÷ÔÂœ¨3Êş”Ñ"ç"²ŒóŠÉÄÍÓCĞ Ü
}0Hp9d\ÿ C‰›¦®9A'µJƒÈ¨Ä‰RG2“‚fÕÌåM'‘N¦ù©ëGš¹â¡˜8+"¥ŒäŠ‰zâ¥YpOœ¢e*d€g¨?…8P)©´¢déX¸ØÉÂã€õ¤
[¥5]Xg5$l§øECFNš!ŠpN~ïéNÜ”»Æk6®`éˆ¨AÏò§`úRÈ"$sY½L¥"®O Ó•0r3H% ò)é*ß•dãs'Pc9"†ızbH;Ry‹ŒŠÅÄÊTÅïÍ9N8zb°n†œ¬QSÊÌ%Mu'Š‘AÇJbH c4ñ.¬åc(!Á9Í=ŒĞ².>`:SÑÔô¬\Lå=€éNÚ})€=A§?Ê³’f2‚Bm=Å9Tg ~&8=ièÃ8â²’fRĞôS€)***""\r" R"***(H`)±¸piûĞr:ÖLÂPC× úSÔœøÔjêÇ¥V ö5›F¤…TÉÉÍ=ãÖ€ÀqÁ§†\qÅc$Ì\Š˜<õ©Q3Zb²ƒÿ ×©Q×Ú²‘”©±BsR"8Ï‘øÓÕÂò¬Y„©TàT¨pi‘º:t©QÔœùVM3	SA³"0É :‚•]3Åa#	BÂ„ª„(uÎôd5–ÆN"nâ¤B;zR«©ïO¸à~U÷1’‹Ûò©	ƒJŒ½Hñ"Y;˜Ê(bÇ’0ãR¢0ãL)ş`ê+96a(‚£œS‚üÂˆ{SÃ¡íX6ÙŒ¢#)***""\r" R"***(ŒÕ*ÇĞşTÅ`¼‚*T™JóÅCLÊQ#ïO1ŒäRE"zÈ™äVM4a$†˜ÔÒùcŞLP;
‡s	@`Œƒ)***""\r" R"***(=c'­8:´ŠUu\=¨w0”EXv=*E\õÍ"2ƒR£ 9"³wFĞ@„ÓÑOCëO.…@Å”*nÌ%«)***""\r" R"***(ƒ§F¤ i€9şµ"Ê×›¹Œ¢.ÆÇjrÅšptôäuê1øÖM³ XñÚ¥ãø:h•3Ö¦YfÛ2”=1ùS|¯cSïĞQ¾?AI\ÎÌƒÊö4y^Æ¦óĞR4‰ƒğ­2"Ì‹Êö4y^Æw¥¤âªí…˜ÅB:N	Œæ‘ê)w¦9®7Ã´Öˆg€
“r€GãFG¨­UÅb0¤`Ó‚9Í;#ÔR3®xdØ6SFÁêhÎhÈõùY-\M‹ëK°zšPÊ:àĞ\uãğ«I’ĞÖ@i›4ıàñKòûUÅŒGƒœv¡§å}hÊzµI€Å\œiŞX=3N)|Ä*Ò'”g•ìiB0§™(ştbÕ«ŠÌLCF¡§½.G¨­"Ä3ĞÑƒèiû†1‘Fáê+Nk÷«¹§„&”<yûµ"ºg¥Z“$fÁêhòÇ½H6uÀ£äöªM±6À˜şÒ”GÂŸ‘ê)U“3LW!1sĞÑå{Ÿ|~‚ñú
wb ò½zş>øı#Iqli²+ØĞàŒÊŸæ¥bšÑ6=XÏ+ØÒ… cO9§ĞV‘l’0¤ö§y^ÆŸ½AG˜£­W3¥òWû¿¥*Ê™ÇZy‘*“dKr3ö…HâŸ¸g9»Ğ}à*”š"í2Æ)***""\r" R"***("¡€jf’<t¦yŠzVÑm†â*ç­;Ë¦h	ü)ÂEŸ…]Ù)***""\r" R"***(Œ°äSdj›ÍR8QIòõâ´‰:¢?,™£Êö5&Tt"— ñšÙ1Şäk?ãOXñÛô§¹È§)•i±;ˆb”(dzş´å TÈm*	¤( ã4ödÏZFuëÇáZ§q«‘í>”¸>†¼zO1j’Ômè&¡¤([¨4ï5=iwCV“!²?+ØÑåûÊŸæ ïJ]JàkXÜ–Gå{FB*O5=hŞqVMÚ"Áô4'µK¾?AFøıZL|ÃV/oÎ"ã¡¡e@işjzÖ‰63Êö4óØÔ‚EÏ"È Õ$ÅqW±£Êö4ÿ 1=i£<T›dİ Ø@R$`ƒNgÿ ­K¼z¤™)***""\r" R"***(»Œ
GEı)p})***""\r" R"***(;xô4	Pu¢L›±¡¹”G½O¦84Ry Õ¤Èrb¢ş”¡OLRïQĞR‰ =*ÕÌ[PŠPƒæŸæGè)wÇè*Ö„óì¦œ#ÇğştàËéÂ¤FŒuª“"Ú}(T9Î;Ôä.sŠ0=W1<Ã0})***""\r" R"***(Y#ŸÖŸ:š7.1Å$ÈˆÆç4,@ğ)***""\r" R"***(HpzNR«ÁZµtC“±ûSÖ6<N¾´ğèER½ÌÜ™FGU¤	“÷J›|g©o‹ÔU™ŒX‰êiâ%Ç"¹}iÁ“v›%ÉŒØ=M8GÀ<R†LıßÒOP?
­Q<ìnÁëJPvCùSÁ@sÅ.áê)rÜ9ÙAİJo–=MK•õ|ÕqD¹20ƒ4ìCOR€ôíÉıßÒ¬vE°·QùÑå‘Ó.äşïéFäşïéT®ƒCzš8õ©.8¥ÈõDº’"ò½WÖ¥qK»ı‘ùSI‹ÚHŒF@¥Ø}jPTŒàP6gœVíÁúôñÏOx®¾ß…hNlü^f$çs“MóqŠ]êzWì-Ÿí¤¤<>[¤F9¡5"0È&±‘„™ $Šr±'˜'§)ÚsŠÌÅÈ™YL¤¯J­ƒ*o3Ú¡œòc‰$äÒ†ÀÅ3Ìö¥S¸gä9E–95 r*(ÎÑœS¼ÏjÉ½L[»%I<âæÓq)èØçjZ¹Ô™X·Z~ü ¨•¶ö§‚JÉÜç‘"‘‘ÏëR®Cš‚7ÚzTòqŠÍ¶a)2Â6x§
rj(ß¥9›pÆ+'¹‹“%ó3Ò®£½WS´çøäñRÒ3re•` ’)wâ£ó=©CƒÖ±{˜·©*È1Æ?rÉ“Ú Ş	Å=[ø@¨‘œ‰²O¥>7
£t¨ƒ£ªÛ1Y»˜9«g®)âLúTğ1Š‘;ÖR³3“$ó	lÖœ89¨ÁÁÍ8>N1Yó+©ºP£t\SÃ€k6sÍ²]ãĞÒïúÔjÙ8Å-fÌ®ÉCÇ5 b8}êjÊFslrÈr3R	A8şµ)***""\r" R"***(
ps•›W2rĞ²²qR#åy•WY8T‹'Ê8¬¥nL²àô§		ô¨ÿ ³úÓ£“•FL²$Ï¥Iæı*´ruâ®3øÔ³hXYëOWÜq‘UüÏj|S( YJ&m–Q¹ÛOE@²Œçÿ 9k#I’«‚y"$ ğsøÔLŒâ+6Œ¥&XÃ©Í(ƒœT{Æ(ó=«6Ìœµ,$ã¥3sUÕ³Í=_±üêlˆ,,¤I§«¹ªèãŞµ “Q$ŒÙeeÀëÚ¦J§x©#“Ú³”L^…¿4ç©§yœgŠ®X“‘NqX¸™I\›y>”äğ*“ŸéOI>n•)***""\r" R"***(H˜±#€ÄS<Ïj<Ïök&µ3dâL§+)***""\r" R"***(AO¥CHÊL™$*y9©`ÕX6Gm8Åg(œóeù8œŠ…$ùºSÃâ³hÁ²ucŒûSÑŠ•“Å<J ¬nc)2ÈÓ·Œäœş5^9¥Hk6Œ¤ÉÕóÁ¥5ÈÉ§	8²’2l[E805ÈÓ„ dâg$‹
ä™uTY?ıU$rJÍ¦dÒE­ç¸§,¾ÿ B%)***""\r" R"***(Úœ$PsšÍÆæV&ÏTªF95XJ SÒA€1XJ&-–D™ OITñP#Œ{zÓºÖN&2-,„*E“š«ñÒ¤I=«&•Œ¤¬Yóµ*È:Ôeò1Š@H¬Lçz“‰³ĞSÒSzUo3ıšzHÇJÍÄÊI––@9§¤Ø9#òª©'ÍŠzJQY¸óW-‰oÒ%Ï¥Tz~´ÿ 9}+9DÂH´³Œc4ôš©¤½ªD“iæ³pĞÅ¢âËÜ
x”õ¥UYFsŠ˜1•¬\d‹BQOY7ëUVPxÅ=dU?ZKJ%´õ"Ë¦ª$€sOĞÖrÏ$Ycø¿ZwšO"«	”œbœ²àò?ZÉÁ4Ë)<S·ŸJ‰f]½)Ë*µC‹1™2¹Ç¦I
÷ÍUYNië(äõœ sÊ%Á Ç_Ê€ãT(Zp”‚£‘œî(œHGCOY³ÁTIÏ¥I `jä‘dKÇzrÊzŠ®%à
rÊäVn1•Ëk #“R	ˆ<UU³ĞÓÃ¥fàdÑcÎ©?pşñüê{“I½}hå3å'ós÷Mkc Ş Ò¬¤sùÕ¨\‡o5ıiVF'¨¼Ïj uı›&Èœ±îhÃçUüå¥û@ÇZÒ1°šEçĞQ¼ú
®% £Ìö«Q'”ŸÌ>Ô†lb¡óè?Z¹õüj”âN%Ï¥'ŸíPùÔyÕ¬bCH›Ïö¥óG·çPy¢”ºã­_"%¤MæûŠ<ßqPyŸìÑ¿¾?Z¥HœÉ2?
2}MB2=})şgµh$‡äúšLó=¨ó=©¨Ñ%§ÿ ¯K‘ê*3Ú3Ú¶Q%Ù‰1ÜQæÓ™íG™íG³'N„şo¸£Í÷ñ”»×Ö©FÄ´XÄÓÖ_Ê«‰8« õÅZ‰)***""\r" R"***(X³ç¯ÓëAqÔUV“=)ù­I²,}¥¿È NÄàƒÌö¥Y 9"¯•ŸÎqŞƒ+õœ´yËM@,‰|×õ¥2ğzÔ>rÒ4 ô5J0•{šU™@ÅWZQ"ƒœÖ±€D¹éŠ_0ÍVóÖ—ÍÈî~µj$5bÀ•sÁ§«~µWÌö¥óO¿çUËqr=E/›î*¿œ¹¥ó=©¨	ØœÉâ“û_­Bd’(Èq€»nÏñ~´Ús‘Pùƒ¦(ó=«hÄ‡7ÜS•³×[9Å9fÇZÑ@N%ç×?aôs/<S¼å¦¢CD»Ï ¥Vã9¨|å¥Èi1ZÄŞxŸhÕ8Ï&“zúÖª#å¹gÏö§y¯j°™@§y§ßó­TÊNÒñúÒëŠ„Ê{ş4†@H«Q°4LfÈéM2·sQyËApã¥h¢î$™'›î)Ë)<gõ¨	­7ÌÁà~µ¢‰qE¬QFÿ ö¿Z®³`ÿ :rÊ­Vš±!|
pbÃ­E½}iVUQŠ¾R%Ï9hó–ª;“f?$t4àäEEç-rÕ
Åä÷¤gœŠ‡Ìö£Ìö«IƒD›Ï £Ì=…Gæ{Qæ{V‘‰$aµkúÔ{Æ?¥gµj’!Ä“ÍZ¬zâ£ó=¨ó=ªÔu‰*¸=)ÂLt"¡ZPÀò)***""\r" R"***(R‰…Ÿæ¢`NÕpäy¥Ğ~´ÒÔÍÓ,o>”õ™qÒ9j¬O)`J09¢P~éªşg·ëNI@ê*ÔHq,ù¾â7ÜTÇaG™íWÊCDşo¸£Ì>Õ™íJ²àò)***""\r" R"***(>QY“y„zR¬ø<ŸÖ¡iU†)7¯­>R]ÙgÍİß¡Øg?Z®²uç4ôœä~´ìÌÜI·ŸAFóè*?3Ú3Ú©EfJ®HûÔñ+*¸“ŸJzÉÇ¯½ZD¸“‰ıE8H_Ò«ùÔ¢AÙ¨q%À³¸úÓ·ŸAP	;ô¡¤Éõ¦‰ädûÏ ¤óµAæ{Rï_Z¤…ÊN³ÎißhÕ[zúÑ½}jÒ)dM“Š_7ÜUd“ÿ ÕNó=©Ù’âÉüßqG˜OLT ƒÒœ$	ÁªJÃå%/sŠpl)***""\r" R"***(W2)9Í85IàYc¸£Í÷ |b3Ú­DÏ”œHO¥8LAäÔ œdSÃ©?0«³d¸Øüg,iq)»ÔœmÍ8ps_¬]íl¥qê¸ëÖŒ8Zxô4å#;³Y6e'bU;NqNVÜqŠŒ{ÓQÏ5&2‘"¶ŞÕ"¶ŞÕ:ŒÓÁ¡¬Û2lzÃ8©â¢B äÒ‚È¨lÊR&ŒS·Œd
dl£¿4ğS95œ¬e)Qº)Ôğ)F;æ³r2rC•JƒNÎ9  zö¥~½*F2b¡$dúÓ×ï
b0{ÓÁÍCjÇ<ÉÑ±À<Óƒ`æ¢G]ÔíãĞÖR2näÊt§€AQÇ"§µ<H¦³nÌÉÉØ8¤gcÒÒ©Áë6ÚØÉ±S§ãR+@ÇãLÜ àS”Œæ²m³6Ğü’0jD;@8íQdzŠxqŠ†Ì^äªÛ»Tµn9©#Vr1‘98¦ïÏÚ5‹¹Ñ*ıáR¯Aõ¨E*e‘09¬¥±„ÇÒ©ÚsŠg˜´»ÅA›Ğ>õ sPoõ e<ÖOc	Éó=©Tç'Ş£Ş)ÊàÇµA›m§ÀÆ)Á 0<f¦F2l”ŒÔˆÛGNÕàT‘ò3YÈÉÈ˜œT„àf¢ sŠy‘OœŒ$ÅYriâ\B89§†¥K1oRdvb	?…H§5>ÑNGÍc(³92Ğ“Å9•X0' T©"ÖRFE…|ŒJ­1Q£K¼zÍ¢¹:H1NS‘œTHÃÍ=dP1š†ˆv	Švş9ÀêijlfÙ*>9©Dœô¨†1š“x©’3‘?™íFñ•˜´	œf±”LY2IĞ~•"¶9]XœÓÃƒÅdâc$Oæ{S‘Æxô¨OSR# sPâc-	êJ¯‹Ğš›ÍOZ‰$sÍ/·ŒÒÆàñïQ<ŠOèœYµ©‹e˜ß§ùÕH»©áÀ¬šÔç–ägµ=ªËëOY¬Ú3l°$ÁéOÜŞµ^9 5)pF+'õ$Ş1ŸÒœ’ãô¨ˆïOW¬œLÚ,$½éNó=¿Z\gÖ•dMß5fãc6ìXIOOj’9qUãuÏµJŒzÎHÊL´„œäÓÃ‘Ö¡Iu4íê{VMÉ“#÷Å=$ù¹
:…èzÓ–E)***""\r" R"***(šÆHÆLdÁ©ÁÔ
ÃE<8™›I“£b¥CÚ««®^•2°=+)E˜É‰yï9É¨‚1ŠEm½ø¬\Z,	8”>N1úÔ"ƒS$‰ŒÖn&Rd…Èšr>ê‹ÌFíK¼zS	jN²2ñ*O3Ú Ş3Œ“zÔ8M’ ğiâNzTÖœ’®95“†¦,Ç&Æ¦F8Îjš?BåR¬«µ›“Eøê?‘éÅUIW=j@àtjÍÀÂH²­·¯ó§0x¨#•Îêw˜•“”‘2ÌOZp”‚ Y74ÿ 1OJÍÀÉ»\€rE=dçÍVI ç4õ‘OCPàe$YAĞŠ‘%QÁª« "’‚pMCÍ%rØ“)***""\r" R"***(*Éß­WYM8:ãp5“‰Œ YzŸÒ”IÇJ®²©šrÈ©q0”K*Ç¨©nÍU•ÇcR+ƒŞ³q2iUû©©¤ƒš¨’*œnúsR‰ò+7™I™cIæsÒ˜\M'š”r3&¬Kæàü´¢cŞ¡óSÖ*õjµr9h3Ğâ«´ŠF¤È=)***""\r" R"***(W))***""\r" R"***(î_Zr¸ÇÕu`½E;rúÕ(Ñ?™íG™íUüÁèiwCV¢"3Ú0w piË"ŒÖŠ,L—Ìö£Ìö¨üÔõ£ÍOZ¥A'™íN'5š™ÆhóS8Í\`'bU”ƒŒSüÏj¯æ§­jzÕ¨bÇ™íA”¢ ©¥Ç¡ªP%«“yËGœAPï†•$QœÕ(”[wj¶œb™©´3«æ´I’ôæ{SÈÍG‘ê(Î{UrÜ—•Iê)¹AÚ—xô5J"jãÃôàHéQo†…“ÓŠ®VC‰;8ÇáQ—…5œg“Mó´QbåDgµgµGæ§­jzÖŠ7)'™íG™íQù©ëGšµJRPIê)Û˜÷¨|Ğ{šÜrjÔ!`)„P¼£ 4›Ç¡­TDZ®94¢Ojª­ÜSƒñÍW(š¹cÌö¥^*¾ñèiCã¡ëO”\¥¡ =iİ*²Éèqõ§ù‹T¢&¬H\vyÕš´y©ëT ÉJÄg·ëJ²€rED%SK¼zÕD,™:Ê­K½}j¸™§, õ5|¢å&Ş¾´gµGæ¦zÑæ§­W+DÛRQ)sTBE<ŠPàš¥Y†,2iÁğ1Šƒxo†¶ŒOæ{Qæ{~µ_x÷¥·ÖµQ3Ûõ£Ìãâ£óSÖ5=kNP$ó=¨ó=¿ZÍOZˆyÍTbKDgµgµGæ§­jzÖ–dò’yÔ	Hè*?1OJ<ÅÇCô«Q*$2“ÔPg‘LŞ=)***""\r" R"***(Ç¡§a8¢PİÁ¥,OSP‰x§‰9§fCŠ$ŒQæ{S7C@aµ¤b&»Ğj5dÎ	§ïQBQæâ3Ú™¼z7CZ%a8¤?Ìö¤fÜ1ŠÜL.cV‘.$ÔT[Ç¡¤ó¡­"ˆåE3Ú3Ú«ùƒ'¯Ò—xô5­‘Bc*‚hó– .§¨£rör¦K‰dLqÅ8L03UÖEÚ9§­@—–7æëµÇz~áµj63pD»ÛÖ—Ìö¨üÅjzÕYfIæ{P%# ıj?5=h+p)***""\r" R"***(RW™/œÔå—'®j,QFG¨ª²)7™íNWşé¨À©ÕzšiÒ%W óR,€Š¯æ)éJOSCD8“‡éN‘P‰f”0<æš‰´ ‘ĞÔ;‡­<8IX—`HéNó=ª.:Ràõ4ÔÊ‰ŒœzS©9ÍG¼z7CW*CÄ˜9—ÎjŒ:šPÊN+EåD«/n´àAéQNÂœ’(Îiò‰Á‡#¯4¾g·ëQ—VSI©£–ÄòØ›Ìö >O" )***""\r" R"***(=\`
« &ÎyÍ9\t5¸—xô4Ò3hœIÀâ€àÔ‡­I¼U¤C‰øÙœsG™“Æ˜Yz¨¯Ô[?Ú"E'wZ~Hã591ÿ ëÔ¹¶H¯Î	íR!$õíQmÏN½ÅI¯¥D™Œ£ò}jT MD¬	È§‚CYÈÊR$	Å.üf£éHa‘Pa&N² :šr¿sš‰@š‘F)***""\r" R"***(fÚ2nÄ¨êNj`ã«  äÔõ#¹5‹0l²‡ÔÓ¹'­C'95)`+7¹”¤; wçÚ”Ï=>´ÑÁğÀœPÙ‹wœ„“É¤UÏ'¥8(fÙ›bäúšz;e*3“PÈl˜9n„ÒäúŸÎ™¯<ĞÍ“Á¨½ŒäˆïNYyÅD¬1É§›¥Cw2“KbQ!>”á'Ö£QŠZÍ™JEˆäP95,nj¢Ï58b:VlÂR&ó0q¸şt1ÜÓ	ÀÉ¤Ş¾µÆL•_œçğ§‰2@Ô
FA©#eÏZÎFRdÊş´äÎj,Œg4äaœæ²2l°’g¿çR‡ÇŞªÑ¸ÏZ›zúÖLç˜ıãĞÒù™¨÷/@iF3‚i;^Ä±±biã"¢R nièÙ=k6Œå"A œÔ¨Ùg¥W	ÆjDn85&2&VÇSNŞ3Æj0ÊN¥¬Ş†r$ÙïO	À¨A9ëNÜ`jŒ‰Ã€9Í(|3QÁ4ô çµg#&ìJŒIÅ?qõ¨wĞÓÕ½MfÖ¦nE…r:“NÏ5 ô4ä`)***""\r" R"***(CJÄ6J¬HëùSƒyéLG\u¥Ş¾µ62“'GS²}juÚ9§,œğk6ˆ& Å89n„ÔA×šz:š–‰iGZp`yÍFX‚h,Á=j¹‹&Y1Ş¤G$òN=êe“R+.Şµ›Z¶JgƒOñŒŸÎ¡‘J„ÍdâsÊDù>µ.ãëP+xÔŠŞ¦±hÂL•_<z0T—<z¸Ç&¥«É«sš”8Çz®®¡zÔŠêT`ÖRZ˜ÉÜAÍ?x)***""\r" R"***(E¹}ik+¶XVÏ"Ÿæûš[®ÓA|¨hÊI2À”g’iÂUìj²ÉïŞ½}k6ŒÚh²CÎœ¬[ƒPDêHùªMà)***""\r" R"***(D’3z“£•<š˜7÷MV¸ÔÇf¬e&ZIæœ² zšXÔ»­bÓ¹”‹Be^ôñ"š¨­µ$L2k)DÎIVLtıiâNœš®©† Ídâa-QÈç5$rõäÕD|pZ¦VàÖr‰”‹QI§yŠzT—j¹±q2jÅ êiÊØ9ÏÈ¤g5":íëY¸™=‰ùæ®É?­C½}hÜ¾µ§4‘d9#‚›îj²9“Rî\õ¨k¹„‘ —¦®Z†œŒ çÖ¡Å=	ÕˆåM;Îã«‰÷=\c“RàdÚdé6{Ô«)îMWVLdÔôpxİY8ÉQÈïRùƒŞ«+`šq|¬ÜŒ‹NùüéV\Õ_0xÔ‘:œÕÊL²²x?8Hs“úT(Ã Ó÷¯­dâc&L²ûşU"Hşu]sœÓ·¯­C“±id©£Í ü§õªë!=iCärk7LÆV,¤™èÕ,OÆ	ªhà7¦I
œæ³•=yÕÏP:p“ÍWŞñR‰@?{ó¬ùy$Ùe\ö9©#”zª‰ äzH½C…ŒåËKšnòzÊ¡2q÷©™9ÎMR›‰cq=õ¥Wçï~µåÒœ¬¤à5>BZ±>ñèi<ÕñQdç†¡[“G),›Í÷4y¾æ£Ş¾´'İkEO+%ó€=M8J¤dšª\w4o£Uò’â[óSÖ1?½UÕ×šBäğ*ãYgÌZBÄÿ õª¸'<µ8H ÆãV G)6æõ§o† Éõ4 dšÕ@MXœ:Ñ¼zƒÌŞ4yƒûÆš€‰üÁÛ4	2~ñüj ÄŒ†4¹>¦©SDû÷¿Zp`=j°v)***""\r" R"***(8JOSV E‹`3G›îjps–§o_Z¾To¹¥‘ëQo_Z7¯­¤ò²q0Æw~´¾pşñüê¾õõ£zúÕ(\›2Ç›îiV^8?VïT›—Ö©BÂjäÅÏ\şTß3=I¦?z“zúÖŠ"å$Ş´ŒùS7¯­#ºj”uĞâÄëIæûšx=ZëëZÆ$5rd”ö4¢CüUğ:5)bI­A"}ãĞÑ¼zƒÌŞ4	3Æê®PĞœIÎ4íÄŒgñ¨U† 'šz°ƒO–Á üŸSN u¨÷¯­×Ö©&ÆIæûšSpMD=)***""\r" R"***(ÀqqZ(Ü†‰|ÿ j<ÿ j¯¸úš7ï~µ¢)***""\r" R"***("ÊË’)***""\r" R"***(;Í÷5^6P@-ÍI½}jÔI$óxÎMo¹¨÷¯­×Öš‹@H%Ç¯ãKçûT[—®hŞ¾µª‰-	ñÀ4á/MWŞ¾´yƒûÔÔu‹o¹£Íç©¨<Ïö¨ó÷j¢Q9— åG›îj Äò)***""\r" R"***(?zúÖŠ7&Ì“Í÷4yæ£,¸àÓr}MZˆ­bo7ÜÑæûš‡'ÔĞ¬:—ü*”DMæûš<ßsQï_Z7/­h¤˜ş#Nßw~µ¹É§““T­qşo¹£Í÷56OŒŸSWÊ.Rpäóšw˜Õ]]‰ÆiÅˆêÆ©@\„Şp[õ¥ó}ÍWŞ¾´àä*ÔGÊ‰ÕÈèsRoÿ kõªÅ—vO©ªP%Åy¾æ8xşuO­!eÕ(âNfp3Mßş×ëQn_Z7¯­Z‰$¢LëFÿ ö¿Z‹zúÑ½}jã\	wÿ µúÑ¿ı¯Ö¢Ş§½×Ö´å!:¸Ç'4»Ç¡¨qÁ§+`j’%ÆÄÀç‘J§“Q{K“êi¤.[“†Çñ~´oÿ oõ¨2}Mˆ÷úÖ‹rK&VÇ&›çûTe94›×Ö®Ä8“	séJ% äŠ…wu§ï_Zh‰+	‰8‚Äõ¨wĞÓ‘»“V‘)***""\r" R"***(‰ëúTŠÿ Ş¨7¯­=d©ªKBIC›©êãœÔ×Ö•Xãå4râO¼z˜îjÇÖ•XmäóMFÂq&O94á#ŒÔ!84ğËMR‰.$«/¿çOŞ=)***""\r" R"***(W ÿ 8³Ö­Sl›X”¸#ŒÒdúš'ÔÑ“êj”™&O©¡[’j5c»“Å;zúÕr*8>ÔıëïU÷ĞÓ‘ÁÎZšˆšL›xƒùQæ×5åëš7¯­]ˆq$§½(lr)***""\r" R"***(E½}iD€w¥ÊO):¿Ë÷±K¿ı¿Ö ŞXP­ƒÉ«Pbå¹>ÿ ö¿Zwšşµ ô4¡ˆïŸ­_).6?©WÎiÖÁõ¯ÒÏöYÈ’œ„cæ™œô4ôQ×½fö2r	)ÈI<š@£»SÂñÀ¬›1”® ‘ĞÔ¡°0)‹<Ô…WÍChÊRÇ&«Ø
E t4ôéøÔ·sÇÆ¤OPM5O R ¿5Œ™”Ç(8Å*¡Æ¡“Ú9èk&ÙŒÛ “ŞÏCH98%ClÁ½B•>ğ¤¥_½PD‰ˆ gŠvõõ¦CHHşõg#õÏıÓB1n¦›ZrwÄä<63ŠUoSM'§*sÉ©r0”®8c<šz *f9Æië€1‘PÙ‹cÕÆ>cK½}i€p)Ê«ëšƒ7;GÎj`Àô5îìjT g&³v2rC÷1ïIFG­! w¬›±›c•°pzSĞ¹¨úô4ğF5-™I’¡¥”Ä#9Í>¥ìdØø™‰ëSooZ‚.µ.G¨¬™”ÉƒNV¡Ü=iTójLÅ´LîäñR+(QÍ@É"‘·­KV2‘&õõ§£r~• ô4õè+&Ì›,#6sš–¡Nõ)`±‘ŒŞ¢”ªFsQÏ©W5&-Ü˜0' Ò‚GJb“NÈõ·3–äŠÙàÓ#¥F„É§dzŠ–¬Év'IxûÔ¥Ãµ$ÒäzŠ–Œî‘0b)Â^>õA¸{õ¥Gç¨q!–\¹§¬„)***""\r" R"***(W©°8¨q3e„~8?Z•d÷ÍUz2Æjldö&”´æ£Î;Òï$ZTe%tJîäñNqò*sĞştõÀl“Y8´a$É–Lu§«ƒÖ¡È=)***""\r" R"***(<Ífãc)¤€õ5"HäÕxÈçš‘p3–g(İÌ—rôàÄt5G­9“Ş£•²Tö¹§		ŠÏZ~G¨¨”Q„›®sÓñ©VBG¢`sK‘ëY4e$J¼Ó‹ÔÓõ§0SÎîÕœ£ØÅèÇ"—{zÔJFáóT™¢±jÄIG9ÅJ²œ`œT óiÊÄMKI˜¶XÉ<zzT©!P#…GJz¶zÖM+ÉÜ²¯èjE“°8¨c#iÁ€<YJ:µrtSÍ=\ƒÉ¨²9"¤‘X´e$XF:óNEB¤ŒŠ‘HÀ›‰‹'Gã“R#‚95@çµ>29É¬å)lMægÔ àæ˜ÁO Ó_Ö²p¹”‰ÃŞÔá!J®	 Ô‹!ÛÔTû3	"u“Ôàç®jpİÿ |gk7	+V@G-O)***""\r" R"***(»ı*°|t"¥V#¥fàc%¡2É×¾oûU›î(2sœñY¸´N%Éûß…Hvà•]lf¬£Rå2‘eã óŞ­‘Ö«£zÔïY¸˜Jè±æ€8jvöê,Z{ƒÏjÊHÆC–@iá»ƒUÆ3ŒÔ€9Vn&M“¤ÄpÔá>sUÕÉ<)àƒĞÔr£9$XYYºSÒB8&¡ˆ^ÔüQY´bö'IïOŞIö¨2:æ”>?ˆTò˜KRÀ=Á§¬¸ŸÒªù€çJ’97u5›‰Œ£bĞ™±J$'¡ı*âœc­fàfâN²0©QÃôªÈİ‰úT±­Ë}êd¬L]€Îi<ßö¿JBF1ši\w(™5qşoû_¥oû_¥GE5	<ßö¿JÃ<š#ÔQ‘ê+EÔVDáÁëÅ/J®S¼ÌR¦KV$f9ùMwı*"äuj<ÃıáV KDÁ‡vı)|ÜD¬1ÉõŒ“V K½z7·­&G¨£#ÔU¨d89iŞfˆTy¡£ u5§#!Ä~åõo_Z#ÔRäzŠj,T<:ƒi|ßö¿J‰œšo™şĞ­r¢ÂHV§o_Z¬²‘ÜrÊOSO‘ƒ‰1
O9j2ÁE%RŠ"ÄÂPz
Q1TH@š\¯¨«Pˆ¹I„ŒFs@r5|pR‰=H4ùr“\u¡HşQ†ëJ=)***""\r" R"***(>R\lLdã¥4Èş”ÂÍĞšBGLÕ¨»ŠÉŞ¾´n_ZfG­µ¢Ã™¸ùM&öõ¤ÈõdzŠ|¦lzs“KQ‡ĞŠç5q‹¸Zä”…€êj<ïRäzŠÑA°Q$ 0ƒ7ûUG¨¢´P)***""\r" R"***(‰<ßö¿JPç¿5<ÍR€¹‘2Éù¡¤çÅEz*”Q7¸æa)***""\r" R"***(Îy4ÜQFG¨­RaáÀèÔ¾oû_¥E‘ëK‘ê+XÂä·bd˜‡µ;Íÿ kôªá€èÂ—Ì?ŞjîËBz5ÛÖ¡W)***""\r" R"***(CI§?5¨¶JXg$Ñæm)***""\r" R"***(PrzÎ7ÜUÆåÓR7ı¯Ò7ı¯Ò¢Îir=EiÊÅÊ‰<ßö¿JPäu¨ÀÏqOÈõªQK½½h,HÁ58¥3{zÕ¨‡)1a)***""\r" R"***(7{zÔ{ÛÖ•Xç“Z(‹•’+y4àHéQ†£
r±'“T‘-"U“ñO2qÀ¨r=E(pZ¥Z±&öõ¥WùEæï
<ÃıáV¢	Ø›zúÑ½}jíëNVã“V¢l“zôÍ/›7Ty¢ŒZ|£å%.Ã©¤óÚı)	ŒÓÁÆkHØMX“Íÿ kô¥ó×5Ç9§dKDÅÉéHd#©¨üÂzH_=XSŠ!­I€õjMëëLÈõVdH=)***""\r" R"***((b:b3“NÈõv!î(võ§¬¹=
#ÔRdv"šD4YY01‘Kæï
®‡£{zÕr‘ÊÉüßö¿J]íëP‚ëRäzÕ¥¨ZÂïoZ7·­!84dzÕ‰¡w7­9¿úôÊ äU%rnK½½iVFZ‹{zÓ”¤Õ¨Ø‡U‘šœ÷¨#¡¥VÏŞ5¢Dò’‚OQŠr“Ó8¨„˜î)Áƒsœ~4ùHpd»€µ/›â¨²?¿KÈëT¢‰q%zæ’1 fè)***""\r" R"***(<r*¹Q.(™[±5.õõ¨ôÅI‘ê*¬fàÇï_Z7¯­FHÇ)¥˜´íryY6õõ£zúÔ;ÛÖíëG+RpAä*bO&z¤„àL_Ò“{zÔ`‘ĞÑ½½jùQ¤›ÛÖíëQïoZ7·­4ƒ”•f`0iÂB{ş•`G&œñÈå'"œ®~µãïS•ÈëUqLüyWÜsÏíÄ3“R!ä÷¯Ñ[±şÄÉƒ*E'®)ˆFsš^A¬[¹“mW$ã(`7võ¨ÁÈ§+×‘„¤Nö9¥VÏ\T úzT½Œe&H® Š‘$ãõªôøÉÔ4ÌîË
ıò*DlŒçš®‘NÖm36îL$=8§«€8#š<š}fõ1“e¤>ÿ ­Hdì?Z®„É§dç9¬Ú¹“dÛÏqHdçsÒ…?6I¬İÌäÉC‘ÿ Ö 6ãÍ7#ÖŒZ‹\ÉÈ™2*D g&ª«`äR‡=j1“'È=)***""\r" R"***((r8ÏçQ†#  ’Nk)$Ì\›dÊÙ‘K¸zÔHxÉ4¹µÄ²UO:çõ¨”®4¹¡¨lÆL™d#­?y¨AÓÕøùª^Æm¢bqßn¾j=ÀõoÖŠÉ˜¹ÁÆ
_0Ô@sOœŒRÒÆm’,¸©Øœf ÍH„¨zT³'"_1»TŠät5
±n´ô g&¡£I’«g­=“P‚;zMCV3\ƒŠz9ÀÈ¨²=hÜGzÍîD™a\œÔ‰ æª õ©¸¨q1“.«çß­<ËÇQU‡×ò§ù¾â±”L[¹)çŠU““Ú—#ÔR²2Ø²²ñÚ—Í÷7n)r=EM™rÂKïOVÏ\Ud<òiâBŞÍI)***""\r" R"***(–U€ç9£yô±iêÙ4™Œ™"¶FM(`r* İFîş´ dâ¤ÉËRe”÷?•Hıª4àäPgÌXØ©B½«)ãƒRèZÍ¢\‹&Rz‘J²ûşUG¨¥)***""\r" R"***(úÔ¸£&ÉÄ¼õ4ÿ 0íâ«‡$óŠz¶0JÍÄÍ²q6q>´øä=1Uò=jUp£‚+)Eòh°®àŠ—Í÷UqÁ T¹Íc%c);“o=Å9eãüj&;çñ¥ó9àqYµs¬N$9íR	Iª°9æ‡µ†.ÄâSœùS–_òj¸=Á©Ï"³q2‘hHzñNßş×ëUÒCŒR™ëŠÍ£	&O¸zÒ«dãu@$$ö§¡ºÔI"…„ëÉ§äc9¨T€ Í;pé»õ¬¥LdL¯¤SÃUÃÒ¥FõoÖ¡Å5bÂËïùS–_Î¡B9æXJ)×RÀ|÷?9$e8ÍAc¿5 `FsY´fË	1'’?:‘%9ÅUƒ‘OVî+9#	V\ÈéOY²r1UA€)***""\r" R"***(H­ƒ€G5‹FNå–”úşf%BXuÏëH$5¬Å·b83úÒ¤§5sÎjHˆãšMI’ùŒ)***""\r" R"***(=go\Ty¢“#=ECŠ3–¨gÇÔ«>ÁâªS’L÷ıj1’-¬Ûºbœ¯‘Éª~fÓÁ§‰‰ÉÍC¦c$ZúÓ¼ìŒîç5Z97H§e}EC„íbÚKÓ&¤õMcéR£·¯Ò²”nsÉ]—|pM?Î?ŞUÈõ§ éúÖ\¦2E '“Í8>?Šªy¾â•fäe¿ZB.,¤OäiË69ÉªÁ²94¡füK“±m'#x©ByİÓŞ©¤„qÒ¤YPZÉÓF)***""\r" R"***(2âKÇQNó}ÅT7cJ³àrA5›…Œd‹BQH¥í<>µWÌÏ9Å=NGZ—)hZ3ƒSE)<úÕ4m ÔªİÅfâfÑud8*Q!ëT–A€)***""\r" R"***(H²2ô5›Œ‘lÏÇJa˜sQ™;)2=E5&¬KöƒïHg,qQäzŠFl­6%ßş×ë@“Ä?:ƒÍ÷y¾â«”—bÇ›î(ó¸ÆEWó	éŠUlõ"œbKØŸÍ'¸¥Ş}C¸zÒ‰1Ü~&¯•LM=dnçj­æûŠCpE5sû_­ÿ ÚıjŸÚ½èûW½h Éh¼%^Æ‘¥¡ª‹)õü©şo¸­jäÅÈ7ëIæ¿­EæûŠ<Ï¥W+TJ$bpM;#ÔTÉ¤ßş×ëT¢.RÀpA¾gÒ«oÿ oõ¥cø‡çWË ¹K"Fí@•±÷ª·š@ê(Æš€œK>qşğüèó¹å¿Z­æûŠ‡ÔVŠ™<¥¡p c?/ŸíUƒ9"œ®@À9ªäBvE•”†¤ Šªcïcñ§,½³ùRQ³-ù¾âšXuÍV2ã¹üéÄÿ ëV fâÙ`Ê3œÆƒ/¸ªÁğs»õ¥/¸VŠ$¸ØŸû_­(sÔÕmÿ í~´,›z7ëUÊ.RÚ¶zâƒ ^õ[Î?Ş*±~I¦¢Ğ­dMæûŠkJ{fG¨£#ÔV‘B°ï5ıië3cï~µG¨¦0q‘Z¨Ü,‹>qşğüéâ\ŒäU?7ÜRùUÈE±.:øRƒÎ*)Ç¤3ñÒ®0&ÄŞkôy¯ëUÌœÒ‰Mj ‘¬œHÄòiÛÿ Úıj ç<Ñæ}*Ô«"}ÿ í~´¢Lüê¿›î(ó	éŠÑCBlX‘ĞŠ<ßqP	=E!”g‚*”F“,y¾â7ÜU7ÜSƒ9"šI”œJİ<HHíP©zÒîŞıi‡*,ãï~´	 î?:ƒÍ÷y„ôÅRC²,sÜR¬™8ÈªûÏ  9ÍiÊÂÈµ‘ê(Èõ_û_­(sj’#b|Q@|wAæûŠ<Âzb«”"Uîhó3ĞU}çĞP²œş•J"å,o>‚•[#’*¿œ?¼:<ĞzV“³e¡&2(ó}ÅVŸâıi|À3Í_(r–<ßqG›î*¿˜OLRï>‚På,,¤M;û_­W)***""\r" R"***(ù¥2×¤R}ÿ í~´¦LŒdUs!î@¤İş×ëG.¤5rvl¦ï5“M?#ÔU$CC•‰5*¶zâ äKæûŠ´¬MÉ‹M,Ozg™½IæûŠÑ-É¡&O© 9›î)Á‘Uf.TH¯òıìT€Œjæ€ÀëO”–‘b—'Ö¢Wà|İ½hÉõªµ‰å&27­cT{Ï ¤ó}ÅZH—_5ıiVCj7ÜR‡ÅRD¸èOæûŠ<Ò:UüßqK¼ú
Õ"9+6=éDÙôªë&:~´íÄŒÖ®ÂkBq/=E=dÀãõª»Îy§,„ñ«Q±“Z–|Ï¥9_åûØªÂCiË/:®QD˜È¥·\Õq&OoÂ$à(°¬XråOû@öªá‡@iÅPîıjÒL‡SpzO9½úÔ4Så'•‰sÜşt4„ É)***""\r" R"***(ÿ ÛıhQÔ\„é/½;Í#¡X>;Š]ííV¢O#,ùÄŒf5»šƒÌã4kúÕ(“ÊZYxëùÒù¾â«,¤H§=Å>Qrù‡Ú&<Upü}ì~4nÿ kõªQM[Ï £ÍoZ¬&n›¿Z~şÁ¿Zµr3ò'9§$âšNM&ñœ
û¶ÏõåÌ˜9õfÇZ>ğ©€rk6Ìå"ElI¥V$â˜­“€)ÊØ5)***""\r" R"***(£M’ÇŞ¤½D«»½>¢M9R† `Tj»†sN›‘D±·Bj@Ù}áS'İœ›3r$Vjpr8¦ ç4êÍ´bÛ¹4dœäÓ÷šbtüiÕ›f2vriC’ØÚTûÂ³‘›wE@É)***""\r" R"***(Ù™¶*uü*XûÔA	ëR #9m™JDªÅºĞX)à)·•–·1r¬Hæ–š?uKÜÍ¶.æõ§©8ö¨éÊÄŒık6g)!áÈã&óQZz®*^†R‘(ã‘J¤’i­Ğı)¨Nìf ÆLzf£¢•‘ÉCOqÖ¡@AÎ;SÓ¯áRÕ‰r'Ï<SÕ‹u¨U¶ö§‚@À5›V1“CÙÙN*»œÔ}éèŠ†Œ›±"€sK’zšj±è8dF*-ÜzôJZEè>”µ“fD¡ˆéJ“)´RiŞä«œã4ú€1)***""\r" R"***((|œb¡¢$NôªÄœ‰NM86NI”™:±<T‘çœÕUm¦¦BNrjZ0m“dôÍ=2G&¢½:¤ÊNä:SĞœš€E=ç¹ndË
r¥¨”’¼ÒÔò²	2GCR†**¸$t©WîŸ¥"d<1'§Zzõ àæ“WFeŠPÄTòqŠt}Y´¬fİ‹¥=z¥B§i©±Íe%te&J„óÍIæqÈ¨·v©·v¬dŒ[H‘I#5"r95 89§«w&R»&@Å9IûÙ¨•²@"œ¤A¬å'tI“œæ¤V pjã½*Éø¬ÜLÚdáÏqNÉ=MD­»µ(89¨hÉ¢@HèjEnP‡ÉÆ)ààæ³h–®Xò Å>««c
x`kŒZ±:½©Àr* ÄSë6Œäµ'W&²08Í1:~4ŒpÙ¨µİŒdXsOY?Æ«+g‘ORHÉ¬¥H²‘œÓ–B:ÔHÍ.Hç5‹‰‹Ô²$'œT¡ÏqUAàš>õ›‰Œ‹É8âUúsK½½jL¥€Äw§#İ*°‘Îië&@8©q1”Ygyô›ÍAæ{S–BF©²3dşo¹¥Y	éúÔ!ÈëÍ:¥ÄÆWDÛÏ ¥BHÍD÷¥Wù¸üéXÅìL¯CR,ŒFqP©$dÓ•ğ1ŠÎHÆM&N­}ªPçŠ¨g)êäsœÖN&W-¤ŒF)***""\r" R"***(;{Í@­@§™8àVn&Lš…,sPo9æœ®2éPàÌİÙadíN0<
€>N1N*Lä‹)<Tˆç*º’½)***""\r" R"***(:>3Š‡îYV$R*>”õ$k7LÉ’94àÄt5$Šz’FMC‰›dñÌqÍH$n¢«†!AÇëG™íY¸™=Ëaô©‘Î)***""\r" R"***(SŠO—¥J­·­K…Œe±9c×4o¹¨ÚLôüé„“Öš‚ œÉÇ)***""\r" R"***(Iæ¿­CE_"%«yJBŠp`zSåD2`ÅzPXõÔIi’äúš2}MBÍ´ã,*ÔqÔ›'ÔÒd¦£§ÈÎi¨´&¬:¤^ƒéQŠ	'¯j¾VCD€‘ĞÓŒ‡°¨hbzšÑD›“o>‚1ª¿™íG™íWÊƒ#ôo>‚ “ŒRÕ(6óè(Ş}CN½Zo>‚çĞSh«IƒĞz’FM-GE>R¬”9ğN2*¸$r)èç?…>A†b8ê„IÇ"UÑ&Iêh¨Û¡Ç¥3{zÖªÃ”ŸŸZB@5öõ£{zÓP±<¤¥ÇaHXš‹­9:ş\¶B²‡zU¿¥6Š¨Ä—aşo¹£Í÷4Ê+E£üßsI¿ßó¦Ó’pj”5ĞI{~´¢V¨”í9Å/™íZ(
Ö&óı©ÛÏ ¨HÈÅ¢‰)***""\r" R"***(X›yôy‡Ò¢GCHy95¢Dµro0ƒõ£Ìj‰>õ>´Q(ğÀğ)ÁŠô¨©U¶ö£•‹—RBÄÒS|ÏjF;qV¢Á«
ÎAÅ9YˆÎj:+E‰xêiC3“Q/İµJr– Ï¥*°j ãÓ#¥R€¬ÉšC×Ú£2·cM$´U( QcÖSœ~ÿ Z†”ÑÊ¤¥ÇaJŒMEæ{Qæ{SI)***""\r" R"***(E"|ŸSI“ëQ+níOBNrjÒ•‡SÓ§ãL¢¨’J*:)¤$É)***""\r" R"***(.öö¨#¥8IÇ"ªÈV&†Œ“ÔÔ`‘Òæ{U%qr¢›æ{P_#ªJÄ¸\xb;Òï>‚¡"—{zÕ¤.FK¼ú
Mæ£ŞŞ´ooZ¥r™õ¤Ş}5	=ijÒ°š÷§$pMGERÜJ(œKÇ$Ñæûš€SƒàcvCä&O ÓÄÍŞ V dw©(Jä8¦L\‘€)µIò’Rî8ÅFi|ÏoÖ©	¡Õ"ôJˆ{~´¥Êt­bµ3qĞ’”1óõ¨–Fjrs“Z¨‘ÊÉT’2iÁˆ89î*‰q$sÈ§‘‘Qƒ‘š(!Ä“$t4¡Û$t§	8äU¤„àÉD¬&Ÿæ¿­CRQdO(ñ!<irŞµi”{3Ö“yôÚ)Ù	¡êÄœpb*5]Ç¯jr®ŞõIjKNäŠÀç´ÀÄt4+)Åh”Y%>µ	”¢œFiòFä»­>¦¢ • è3TrX‘z¥8Iµ©+Ucò.“°¦î$çùS·g 5ö-Øÿ Z%!iÊxoãHƒšŠÍÊæ.mŠ
z”19¬ÛV!²_3Ú¤AÅA'“Rä†³zÉØ’œ?‹qõ§+:ÔİÑ(8¥ŞŞµO©§¯İ©‘)***""\r" R"***(Ø•Y€È=©ë&& æœ‚*1r,‰H§‡ÉÆ*ºs“Sk7dfİÉ¨úÔ•]eç©©3“YHÍŞäªpy4»Àè)ŠN-d÷2œ‰Nİx§yÕ>´ä$ç&¥ìbÙ>ò8ş”œç9¨òsÔÒå½MA›l”9hY9Í1sZZÍ™È”9# Ó‘Î
…w€qR!Ö“hÉ“+f¤VİíQFr3RGŞ²mÉ²Bã°Í!aÙi(©0rXOéÒ˜ŸxSê^äËp¥GZJ*Hm.J‘\•MzOc)õ§î)***""\r" R"***(GNNŸfö2h‘d#¯çOÇj*z}ÑYÙ2C··­=XÁ¨éCIÄÉÜ™eÇµ<ÉíPÓÙ€â¥ÄÍÈpv'§€AP‡9§dúšS6Éƒã¨¥VÜqŠ‰Kddšu+6®J´ôö¨7šr19æ“3—‘`JGô}Üu¨éOW T3&Ñ7=…=8QP+“Î{ÔŠÄµ6f-“ÀÆ)áÛj¸féêÇö£”Í¶XRpjJ¬²â¥W'¡5-¹X˜¿aM$´…À 6zSÊfØä' f©Ïjœ»‰ïYH†Ñ2KŸË¥=_w¨T€riêÄr+'s98Ø™d óRoÿ f«¦yÉ§«ãƒøVr]Ì$L­iáÈóP«“ÈÍ=Ia“Y½v!’£¸§	=ªHéJYˆ¬š1‘2Éjx“•X1éÊùïŠ\¤2ÂËø§™9Î?Z¬ÿ ?'ÔÔ8™²u“¶qNsÉ¨qR+gƒPâg'dN² sùÓÖOåÒ¡F-:²•“1{“‚CR+nöªÈÄœT±³sÍe$ŒÚ±f9üéÅÉéPä†—qõ¬š2™(r:ŒÓÒCŒÔ*I4ä'8ÍfÑ‹dÂcŞ$ÉÎ*Ulu¬š1h´’àJ’ÈªÈTÑ³sÍfâfÑ9š18ÍEæø¥ó¡©å1‘8r)D¤t “'4âI¤àbÉ·ƒÉ4å“ŸZ¯½©Q‰8¨å2“,	=ªO0ãıjbİiêøëK—C¦J­iáÏqUüÂ>í*È{šS	)<æ§yàõªá\ş´£qç5”‘adqR$¤{Š¬¬Â	ÇZ‡-,Ş”ÿ 8TG+Ôš¸íšTa(“‡nôå~x85[ÌnôåsÔ‰DÍ«—nÌ)é&zUEf#$Ô‘ÊG\ô¬œLd¬[‘OYTò)***""\r" R"***(UI9ÉéRô5›‰Œ’e¡+ŠU”äTÉèM(r+7bÕËjäŒŠp~ÇóªË)Ç)***""\r" R"***(OIsÁ¨q2p,‡8àñJÖ ó1ÀÍ(—'üjL\KK Àúv§¤¤öéU•É‘_=)***""\r" R"***(fâg%ro3Ûõ È ÉKè*i‘¡DÏ”ŸÎZÃ±ªáy4¥ıh¢Ä›Ííº•&aŞ«†ÁÉ§+äñV ™›,yÍN– VÇ\Òù€tÍR‚$›{zĞô" iˆèi>Ğİ³UÈC±g·ëJ% uªÂW4åbFsO–®N&'© ÌGz‡{RùƒĞÕ(‘ÊÉÃ°9”ÉÏJƒÌ÷4ìŸSZ(…‰KäcÚfO©£'ÔÕ¨‰¤HŠ_3Ú¢Éõ4dúš¥r“+n8Å<9yªèÇ8Ïj‘[sT ¤¢SëGœÇµD_Ò“'ÔÖŠ*Ã±/™íJ& `
‡'ÔÑ“êj”P¹Q7œÔyÍéPäúšPãÖŠ"q,‰›(°5 c´ıãĞÓå±6$31¤“Ò™¼zO0u¯•”˜94‚@:ˆÈç½&O©ªål9IüïÒ•eÏ½V.@É&1	¦©’Ò-o”ï4c ş•Uf'‚ß­;ÌÀ?5R¦Ñ-"f‘šše`qP´ØèZi›=jÔfOç5!¢ ó}Í/›×5¤b&‰¼Ïjp=ê¿Í8L¸ûÇóªåb²'Àõ§cUüßsG›îkU¢Z'2“ÔQæÈ —Í(›'ªP)8•‰Å;{ûTCœÒù¾æ©D\½É·¿sJ÷¨<ßsO×ôªåĞM$L$,84TjÙéš\ŸSN(‘æM¼øRyÍLç$š+eb’Cüæ§b3šŠ”;ÓpNÍ(v9¨ƒu¥Éõ4ÕÉ%ó=¿ZäãÍãĞÑæz« % ED$ÉÆM)rrjù@“­›îiVRNëO•ÊÉƒôõ—=óP	=E88^„Rå™7™íG™íQ,¥»Rï>‚š‹! |œúÓÕ¶Œb«ùŒÇ­=X‘œÖ‘ˆZÄŞgµgµE“êhÉõ5V`L²âœf\„84©E‡ùÔyÔÍãĞÑ¼z|¡ÊIæœcgµF[w¯ıïÖ­D\¨•[qÆ)Áˆà…w¦“êj¬ÉkRQ+Š<Ïj‹'ÔÑ“êj¬+"_3ÃJ&5G&–©GAY	23ŒÒ ’j,ŸZ\ŸSV‘-zS·°ç5\1 b?úõvD8“yÍG˜,j-çĞP÷\¤r2Q&@Í*ÌIÆ*-ãĞĞ'€jÔEÈMæ?÷¨.ç«Ty>¦ŒŸST¢>TJ²â²çßŞ«‡"•d#¯éT‘‰d8ïJãƒUÖA×wëOÄÕ¨ÜÍÄ›{zÓÖRG-UÃ3“N ç5\„òêXqÒ3Ú ûš_?Úš‹&PdâR;Süä÷ªÛÏ  ÌAÁj!À³ç'j]ãĞÕQ8Ï"çïÎ©BÂä'2(Å ”€*û9¥üj”U„âXY;S¼Ïj®$#ƒKæûŸÎ‹2KN1ŸÂ“·ëQ	7£qõ«I±Y"e;†qKP‰ş”àÄŒäÖŠ#%ÜÃ½*¹Ï&¢Éõ4#½\bDáˆzÊ{šdÿ &OzÑD—òGvâ…b¼SŠp)»Ò¾¦ZŸêËÇ	;Ò‡nãó¦¢ƒúSö7¥fÉl7ZUÉ<“ùĞÖœè*ŒÜ…FjPüi‹}éÅx¨•ŒÜ…Ş=)***""\r" R"***(9[#‚iªÈ§VmØåaÜdÔªwš‰pİêE`ÖnLÍ¶ÇQóšföìiËĞgÒ¦ì†Ñ($ƒNóœZmy¤ìe'bAÁÍ8JÂ¢Äiõ›±““%Y‰Ç4ñ!' š>ğ§‡À<Ö/s94K¼Ó‘‰ÍD®sór¿÷MC3l™	9É§SPÔĞÎsòš“&ĞğÇÖœ¤‘š	#“š‘>è©‘”˜äëÏ¥H€L@sØ§GJÉ£&ÉÔ 8§§ š2Häö©EdÓFrETjÌ°})***""\r" R"***(*±Ï&’Š±›ØqJMÇÖ’•@'šOB9ÎMH„óÍ4(8);4fØıÇÖ—ÌaÒ˜»¿Š– ÍØ‘ğXÔ‰‰>è© úT=Ì'&…Éõ4àãæ›E#6Û%Ü}iKŒqšmìÍ»ŠŠ‘dÏzŠ•>ğ£•‘tL$
3J$,8¨éS¯áSk‘+®IäŸÎœ2:T`r)***""\r" R"***(9	9É¨±‹Ü”Hâ²ãùTÿ 
’>™÷¢ÈÍîJ¤¯J‘àƒ{SÕÛ†¬f÷%Ş}<3c­@Š;c­-Le¹"°ş"jeprWñªÈIÎMN¤ G­+È›x<sJ	)***""\r" R"***(GN{ÔÉ#6îH¬IÅ<1¡3Á§noZÍÄÉ¶JŒIÁ©ã‚*sšvöõ¬œt!»“	 éšxw•WBNriá°0+"/˜GNYØƒ{zÓ’95D7bapOzx¸8ÅW§§İ.&l˜¹aÅ*·©¨ƒ‘O#5‘Ä¡ˆÿ ëÔ›­ERVrºzî9çğÌsQt§+pk6e(²d—)***""\r" R"***(?Í÷5 àäRïoZ‰#'bÂËïÛµJ’ã½VúTˆÀu5*Æl°&cĞÓ„¤õ&¡]Ø8åİüU&2±0›©ÂlzÔôû¢³q1’E•›#µ(bjº±^;zTŠç³qFMX±€Œ•$+Şª©#zÔêIëYÊÎ[“=sH$ÈÆi…›Ö“¡ÍfãcIæ•=M(œ‘×õ¨‰ÉÉ¢Tc$N³üÓÖQ×ùUPHéOG9©q1h²³•§ù¾æ««gµ=_ûÆ§•I2_7¶M/™†ÆjüğiCRâdË.G\S„Äüê¸b;ÓÈÎ*yL¤‹_sNYÏLÕpäSÁÈÍC‰‹E&zøÓ¼×õ¨—¨úÓér$g!şfFrjH¥ÏSPŒdf>^•R,$‡ëJ‡CP£tçšvöõ¬œZîN’‘Ğşu$s1ïU•³Á§£êj4dâ‹K1Ç)***""\r" R"***(Nó[=j¶öõ§,ºVnŒÚE•õ¦Ir2j˜•€ÅJ“+7)$Yó½¨Y2x& WÏ$ñN)***""\r" R"***(“€j$¬ËQËÇSR$™êj¬rÔÔªİÁ¬œŒe©9uÃ/ùÂäÒ@À¦¢g ÿ 7ÜĞ&Ç­2‘³–©E/ŸíBÊsÁëÚ¡%ÇZMíëZ¨#6µ,ù¯ëKç9ı*º9íO2qÀªP%¦Hd$ñúÑæ5E½½hŞŞµjå'Á§‰xêj°sÜS–e£•’àÉüßs@Ÿâüê(<N”Ô	qdèzäÓŒØ8¨C‘×šRÀZ(“ÊKçûQçûT[×ÖëëT DË.iÛÇ¡¨ÿ 4»ÛÖ­D–µ%2ã§ëGšşµöõ£{zÕ("a)îMo¹¨•ÿ ¼iw¯­iÈ;"O7ÜÒ‰°1Š‹zúÑ½}j”È”Mß;ÌZ„´¡Øw­=„y¾æ•e÷üê3Ú”zSP"Í'¿åM2c¹¦³±ééÒ›ó“Ójl“Í÷4á/GãQPHš¥ ³dóš7CQ3Œ|¦“{zÕ¨ˆœCJ]±P¬¸ö§™0:U(’ÒC‹w&˜X“Á4Ö“¿·Zg›ş×éV£rI•$Ó†;TÉç4å—
qíZrÓ%¢£óÚı)w±ïMCRI0ïùÓê-ËëNŞŞµj >¡¦ooZ7·­R@HŠ7Z{zÑ½½j”DÕÉ°y4ğ})***""\r" R"***(A½½ièäçSåĞM"usƒÎ1G™şÑ¨Õ·v¥£”•aşo¹¥óÔş5j L$súQæ-D€h{Õ(Ü	Ôœ{S÷CP	xëúR‚íıkEyY.ñéIæJJF$Šµ;!şcQæy¨··­(r#5\dK¼z€zÔ;Û=iU‰<š-b’'WÎiùv5 $t4äàŸÎQ´K’:2İš¢3Æ9©ò²lÉÃŒ`õ§+62)***""\r" R"***(WYI#'ğ§¬¸P3j¥YooZO8ûÔ~oû_¥4¹=*¬ÂÈ—Í÷4íÇÖ¡]ßÅRÖŠ#'ÔÑ“êi(§Ê‡ ŒÓ¼ßsL¢­D–®É„œir}MD	)w·­Rˆ¹Y v»Ï ¨ÁsÒŞVŠ9	<Æ(ó_Ö£ıå¼¦ ƒ””J{“@“=ÍF3iÛXö«Q‘ b)ë)ç­F3iU¶ö«Q#–ä…˜´›©¦ùÔyÕj$ò1á˜w§,¤‡{zÑ½½jÔAÄ±æÓy„ôÅ@®sór¸ÏÊj¹IäDÛÏ  ?¨¨Õÿ ¼iÀƒĞÓŒIqCÃŒô§«¨Ê¡§+ 95j"qD¢Lt&%\u¨7¯­( ò*ÔHqDûÇ¡¦†aQ†aŞ”1=õ£•’âL²ûşt 'ŸÒ˜N9¢©+µmÇ—Z<ÁÛ4Õê>´â œ‘T•ÉåB¬‡¨4õ“‚Zˆ®9QÍ °?5>R\IÃŸ\Ò‰=EB	ƒOBNrj¹	å%Y20)w7­1M.õõ«QMÏ ş´õ-MF$£~”¡Éäµ.FI¹z2}M1\c“Í;­Z‹F=Xc­H7 ©U¶ö­Iä?&;
)›ÛÖíë_BÛGú•ÎH1N	À5ö”>N1Pİ‰u0ÇqN:c$t¥ƒÆ+6fæOæÿ µúR‰Aè*ïxl
ÍìC™/™íG™íQooZ7·­A<ìeÀäÒù„ò?•B¤•É§ÂàT5byÉCrÇò§¬œqÍWŞ}=XÁ©l—+–RPzóOgäÕdvæœ\çŠÉ»JLœH Ğd#«T!ÏCK¸ŒÔ™¹4L%Ï­9dÅA@$t¥dÌ¥"È”1R#/<ÕDvÏ^Õ0îŸÒ¢HÉËRÈ“'ƒÓ­8H&¡VÚ)***""\r" R"***(Ø÷ı+39H°&â²ç­UGÀÉ<Ô‘ÈI†e)ÖLŒí§o_Z­æzŠp9¬İÈsE•œ/©c”c“TÃñÒ¤V<’zT;™Êe¯7=èóÚı*çµÛÖ³ºFLŸÍç©ÂCÜUts;úÓË„Òz‰²UbÇ¥VÁàÔAıE*9'RÓf“,+gµ<9E@$¡Å8HOCJÚJl¹=8¥Wãæ5öõ ;g­IW'W$|§ŠzÊqÉı*íéFöõ¥k™I¶Mç59eÍWŞŞ´#¯4Y¶Ë‚QÜÒ‡cŠƒ{zÓèqLÍ²U“4ààƒP)***""\r" R"***(?zúÔ´I2É‘¾ô«&Z€0' Ó”í9¬Ú±2jÅ(<
rËj®sÅ=	9É¥cËÁëÅ8J Ô°1Šr’FI¥c92a('ŠzKĞ~•\zSÓ€¨hÉÉùÔå‘€j¾óşE<:ã“K–æR,,€w©–C¹ªaÏ­K¹A¡ÂÆ2Ôµæÿ µúP&õ?¥A½½hŞŞµ)***""\r" R"***(–<ì‚)ÂrFEUŞqJ$ìßCFl´³y§‰³Ş©ùyZrÜÖ³qV3i¢âÏ´iŞy#¥SîëúŠzHGş•Œ¢K-	‰êiË>8WÍÏñ~”»Øw¬ÜHjå±)<Í<JÃŠ¨’ôü)âR©q¹Å‘!<ƒR,¥†sUb\Ôf~íC¦e"Ø—Ÿ½Ry¿í~•PHIëúSüßö¿J‡s&İËoSúS–^àU_7ı¯Òœ’t?­g(¹hO“È§,€œUD¹8œ%ÁÈ›‰œÒ.G.7S„¼ıê¨’‘ĞÔ¨àMfâs¶[Y°:Òı£5XIœ÷£{zÔXÅÜ¸&æ”OØUU“·J]ì)***""\r" R"***('dËxÆ)***""\r" R"***(*ÜsUR^Şİ)á¬ÜÛ¹q'ÈëSGr+=\Š‘eÏ Ön4_3zA1ïU|áœĞ&ª39"ß›â¥öª¢sœJ%ÉÀj—4Yó@<ÓÕ³Êš©½½ië6T8™H¶²cÚ—Íÿ kôª‹9§ù¿í~•<¦,y¿í~”y¼guWóÚı)D„ô4ù43{Ò`$S…ÀU5ƒÉ©C‚2MK‹¹kÎSOñÖ©ƒÜS–FZ‡C/,á‡5 ˜ç‘TD„v§‰2rµ.&REÁ:ç¥9n<Õ?8´¾oû_¥C„“.‰À9á>îõI%ô?8HIàş•2‘ugÇzx”¦©‰xûß¥=eÇµC‚2eåŸ4ºqU¢¸íø‡'bÚÈ@äÔ‰8èjŸœŞ”õ”jÍÀÊH¹çíx§¬ø<ÍRóÚ¥x5†-j_YÁê*d›ÓšÎIÈ&¥I½j%LÉÄ¼fls»ôªFãÒ“í>õÌÍÀ¸.2i|öôªBà“Kçµih,‹fà)***""\r" R"***('œµPÏØÒ	ÀéZ*d4]ûO½/Ú8â©}§Şœ&$sT©ŠÅ¯´ûÑöŸz«æÿ µúQæÿ µúU¨”´.2qOâ©‰TñOàuı)ò	«DËR	—HHOFı)êsÑW³L–\[ŒĞfoJ¬´‚84Õ;´™cíu \p*¯œ3Á¥¨9«P%¦\I±É4¿i÷ªnáÉâëëZ*aÊËi÷£í>õSzúÒù¿í~•J£å-ı§ŠO´ûÕun>cúRï_ZÓÙ¢v,	ÉéJ%=ÍWÑ¿J<ßö¿Jµ±1ÇyÍU<ßö¿JQ.O­_ ¬‹BsEH·š¨pÿ ëSüÀı*”IjÅ“.9È¤ûJÕrãnöõªöd–¾Ò;ŠCpÁTËƒ‚Ôyßí~”Õ4>[¢Ïœ´yËUŒ€õoÒ“zúÖÌR×¾”¦`FIªÂBz7œUF˜œI@OKƒœT[ÛÖíëZrX9Fa”yÀpj¸r:óN)***""\r" R"***(‘i¨âËÔŒæ”JSU·/­/›âı)òâZYÀ4ÿ 9jöõ§Õr	¢Ïœèó–«t¥ŞŞµ\¡Ê‹rw£ÎNõ_{zÒ‡#¯4ùBÀrÈ£½VY æ²)ïT K‰dJGAGœÕ_rôn_Z®BKsQç5V/é@vÍR‚*-yÙïŠÃ¹¨¶({ÓQ°$ZYqÈ ”ÕPKÖœµj,¥ËF^~õ#K‘×ô¨w·­#9Ç5|¡ÈJ]‡zÃÕrç<Q¹½iò‚cÎZQpO«‚ßÄiCÎj”
I<æ£Î8çŞ óÚı)D„ô9§Ê;"7ı¯Ò”HOCP=Å9dãƒŠ9I³%ÀóÍ8KŒÔ>a=ƒ!M5É±?›ş×éNqÒª‰‡sNûF*”¢Yõ'œÕOÎoJ_7ı¯Ò­Bàâ[óš—Íÿ kôª~n‹ô¥ŞŞµ\ˆ\¨·æÿ µúQæÿ µúUUrNüiÕJ(,‹oû_¥/œµX:RïoZ´Y~ĞOJ>ÓïP‚CEiÊ…ÊL.	8å—'“øUzUf~•J³-,€súRùÃ×ôªêíJ]íëO•‹”²% §#ÜÕe ´ğäuæ©"ZDÎã?…0ÉÎ:Tm'·j`“•ªV$Ÿ{zÒ‰Ô[ÛÖíëWdŞfO4	 èjíëFöõ§Ê…Ê‹+"µ(UĞ“œš|}ê¹IåDŞoû_¥\œı*:)ò¡r‡aÖ®Åxâ GøRùÅE4‰q'ŞŞ´o?{ô¨~Óï@”‚©DRÒN­Öœd'­UCK½½iòà™d94¾sUPÍM?#¦j”IpH°%=Í!“=[ô¨2G"—{zÖŠ(RÂÉÇ\Ó¼ö=ª®öõ¥BNrj¹EÈZdsKç-WGCFöõ«Q°¹K"Pyœ²`Â«,¸qJ%ç­R+•„¤v§	½OáŠ¬%ãü)|ßÒ´HRĞ”Ôõ—>õPIÔõ“=óWdCù?½³ĞQ½½©›òp:½§sı;rCƒóÎ)ÁÕNx¨è¨w3æ$/»ŒŠPH9’§<Tˆu=«'¹.CÕ‹u©LÀ.óè+6ÙŸ6£èÈõ¦o>‚œòi\.ÉC8Å80#’* N8oÊ¤c“PİÌÜÉ2=E89G¨¥Ü}MD‰ua\/qNŞ}*\’zõ©2rlKÏQNYx {Ô@¤İˆsdÆzšZbğÜÓ™±Ó“vf2 x©#sÏ
±c*HóÎi7s7fJ²p?:~ş9Ôq÷§Vos)1êI5$oŒTi÷E9>ğ¬Û1l˜0#9§8â¢§+à`Öm™¶ÉCd‘R#rÂ«o*’FMDŒ›,n´›Ç¡¨·ç4¡ıj,Œù™*¸Ïğù85`Aàäœ.d¥€ïùP%ÚzTy¢‚ÀRHÉ»’‰³R$ƒµVV-Ö¤ïøRhÊNÄŞo©¢U5)***""\r" R"***(6F|Å•`
Rş‚ F M8H{b—).D›Ï §+g­C¼ú
Rş‚„ˆr'ñŠ—Ì9æ«+©7ŸAG)‹“%Ş=)***""\r" R"***((pN*1½*±'T´ˆr&àŠxpzÔ àæ—yô¬ˆr'È"¤YoÖ«ƒN{Ô8¡n‹g88§ Î{Ò‡#Š‹3)"Àb8œ& c
ÈHãõ£yôY£7Y©éFşy“ŒÓ„¸©ØÉØ°àqNB)***""\r" R"***(B%ã¨¥WÏZ¹›E¿7ÜQæûŠ¯½½o¸©qv2,y¾â0õâ«ù¾â•esY´ÉjÈŸÍ÷o>‚¡VÉÅ9[jH{¤€—Í÷UX·Z‘X·ZÎQĞÊDÂB})ë/c¯z€1—ÌÅgÊIa$ç<TªÀŒçõªªçb²ñÚ£•I2}ÃÔ~tô—Ua =Jz¶G“D4[I€äô§™W±ªˆçb$=ÅfàŒ¤¬OæûŠrÉÏ5XÊŠpŸ5¦mØ´&AÍ;ÏöªaíŠzIüª\2lµ¼öéRÇ/Ò©Ç!Ï"¦VÚ~µ‹Œ‹k ?Z_7ÜT`Ç"“Í÷›…Œ['3`ô§-ÀÅVó	éŠ<ÂzbK£6Ë‚\ó‘NöÅSÇŞÇãOúŸÊ£†®] 
w›ISäuõ‘ˆ Ô8Õ‹bà‚æÓQdÅJ“qÚ¡ÄÅìN$ ç"Ê:UDÙ8Å9\çš‡"Ğ›4¾o¸ªáˆ9§ŠÍÇS±`04ñ*÷5X9y§+éSË©Œ•ËÕ†A¥ 0ªà‘Ş”9r™8¢ÈzS„˜U•¸äÒî'ß­O*l‰GBØ¸ cŠp—ÜU=æœ®OSô¡Á»u.ı )D¼õ[ ô4¾aïŠ‡ÄJ%±pJQ0'‘U‚•d'ŒÔû3Va÷F)Ë.xªhç¹üiáÈ=j=™Í$\Yá…=\„UA!#µ=dÏÎ³p2jÅÁ(nx¥ó}ÅVWÛÜS·â³q2h²³ÇzzMÎxª ç‘J®GZ—\n\ó}ÅBzb«‰	èä Ô8™8¤[WàdT‹ <š¬²qŠrÉz—'ÉÌŠ)<ßqQIıi¾jzÒQDrØŸÍ÷y£¾*5=hŞ§Ö­DOb7ÜQæûŠ_'‘ê*Ô.È'VÏ\S•±ĞÕpÄSÒN¸¦£©-2mçĞQæÖ¢ó}Å!|ÿ ëUÊ¬˜J€ÓÄ¹EVÈõ@àÕ¨‰Ä³æûŠxŸ§U_ÔSÄ£‘UÈˆhµö€Ü~t†AéPo\Ò™¸Æ*ÔåD¦R=)Ù8ÅBdcG˜ÕjÊXInqOó}ÅU°<Ó„Àöıiò•–<ßqG˜OLT
ù<â¸úÕªaÊÉÖ]£¥óıªŸSFO©«TÅÈXgÓñ J3É_'ÔĞµJÈYóSÖœAU.{
Uv'­Ii„â'õZ¨Ò‰HëøU¨k–¼şzPf`Šƒ'Ö¿·ëT .FMæ®zĞzâ«ïÉÇó§)?ŞüªÕ4&ó1OJ‡éJ€U( ²'ó€è¿¥)nÕóè)D¡z
¥‘>óè)<ÓĞâ¢óı©€œóO9I„¹èE<MŒUa"ƒœS„¹ô«Œ	³&óõ¥ƒÍ÷¢B:ş”ù(U§ëŠ„6G4Œå¸¡@‡IüßqG›î*±b:·ëFÿ ö¿Zµ.BĞ•qÉ£ÍOZ¬­ÏŞıiù¢š‚Bo5=iC©ïPd†”1j*Â²E€ÅzQæûŠ„ËÇzMçĞP¢O)?›î)wŸAP+drE(nÁªÔDà‹/E/›î*¸r?.óè*¹I±`J;‘øSüÜwXŒÔ™µJ$Xóı¨3dc›î(ó}ÅW")0pM88•_Í÷äu§È'bÄŒJoš=¿:<ÑíùÓ²V:œ„äÔ~`=ëJ­ºP·r\QFG¨¨èªQ@ì?#×õ¥Ü=j:ir*”‰²=E¡¨CúŠp'Ÿ írubİiN;T+'<ÊçûU(îIœsKæûŠˆÍ‘ŒSwŸAUÊ¾å…˜“Š_´
¬®IÅ:šŠê>TXf—Í÷uëÚUÉb^å„vıi|ßqUÃK¼ú
ÒÈDşo¸ IÏjƒyô¡†2MRˆDØÅµ@â”?¨«å°‰	Å<OÏ" qK¼ú
¥™“™3ÆE `r*:+ND$¾o¸ J;‘QQORo1OJPÀœ
„E9d ÿ 4ƒ”˜1^”ôvıj0ö Ò«“×šLVdşo¸£Í÷ÚdwaT£p³&ó}Å)***""\r" R"***( nâ¢g=iÛ3ÎjÔDĞê(Så¹d™¿­/›î**~ÁêjÔP¹y„ôÅ*ÈsÍ0.:KO”N$Â@zş”»Ç¡¨)r}Mh¢K6ñèiD£° Éõ4ªGvüê”¹Ï ¤ó}ÅE“ëFG¨«Q#%ó}Å(sÜT9¡£$t4ÔC‘–^;~4á'¯éP)ÈëNcŠ´„âË*ür)ÊøäsP,‡b”I´Ò%Äü¨.£½'™Î1M¢½^cı,r½}h¤ànÃê(ÁNM+²9Ç’1À§¤Š¿•BÍ¸c¨I8ÏjÍÚä9“‰Aè)Áƒt5
¶ŞÔåmÃ¥CDsêHÎµ4±&šÍ´ãÒí)***""\r" R"***(fÓ¹.dªÊ	¥Ş¾µ$õ4õè)4fæL¥O'¥8:µæéDÕ›V!Ï¹e[=©ã`ïUĞ“œšš¡¶ŒİBEtô§ïSÖ ¥O¼*[d9“nS€:Ó“¯áQƒšw™íP÷"é’’SNBrjmÇ¥'ˆ”‹(ê¡Æ9¨A `PKÌ\Ùee=£bª£cŒT¨NÍCHÉÈŸÌö§‘š„9‘šp9¨q!²N;ÔªÁ{Utq9©¶Ô4c'brp2i¥ÇaLi2}i7û~µ<¬ÅÈ•d äŠp˜‚ ó=¨“ŒTÚÄ½Kgµ(`x¨	­'?…·bĞ(:x”*¡uŠzËù¢×ĞÆReŸ3Ú3Ú«ùÔàAéEš2z“äSÖA´`T
àN)***""\r" R"***(•À<Tµ©-“yÔ¯_8©œ*mb,	ëRyÕQó*PpsAŞgû?­*8È?¥Eæ³J2éS"dX;ÒyÕ™íúÑæ{T™=ÉU·bœ­·µD3Ç¥;Ìö©oQ£Óš_3Ú 1“Iæ{R³%Ø´²ªŒS„€öª ÷œ²×ó©jæMÜ¶$„äæ Y2=}é|Ïj\¦E…qŒ8<ÕPÄŠzÉéÅ>TCE£2‘ŠaqØTBO4àÄt56fDÈã"¤W^§òªŞgµ9]ŠñÅC‰)***""\r" R"***(–Ær)ŞgµVsÍ=dçx¬ùL›e„p:TˆãµWÈ=éC‘×š‰DÍ–|Ïj<Ïj¯æ{R‡ê9@°’|İ*Pr3TÑ‡ŞŠ•dùsŠ‡'É*Hß•T>{TŠãÔrÙi$)ÅıVWÛNŞ	À¨kS	îK’zÒ† ÔD€2hWâ‹#¡edàqNY@<Š®;ÒÔ8™½K"PjA(=ëTÃ‘ÖŸ uâ¡ÄÊH¾“)ÈJ®% ¤3ÔTr\ÅÜ³æ{S–eUQ(=Îx­'ì\óä
Ÿ…@™Ú3OE#“Y8ËN4rJª®1ƒOVÛY¸³6[£vÎIâ¡ó=©LOzÏÌ²$d
zJ1ŒU5˜îëNYFìœÒp2•ÑqfÁäp”‚ªyªzS–Rx¨p0–¥Å›>9—â©$Œ¼TgµKŒerà”‚3Úª	ˆâœ²dzûÒ³fnåŸ3Úœ³ 1Š«æ{Qæ{TòÒeÁ =©w¯­Sæ$ã8¥Êfâ‹É(E)”éTã™¹ÍI½»Ô8£FÅ2”å’*©“¶)é'AúT´e$YĞSÒ^pEUó=©Ë.x©åF3‰me äŠp”‚ª‡­9e9¨qFĞ½ËŠx”ƒõª"Bz59d*1YÊ3jåå”È§	ŒÕ4˜ã§‰â³p ¶&UâŸ½}jªÉÇJpqßŠŸfdÕËk.ÑÅ<L¹ÅSx ÓÖoïT¸X‡Z/‘ŒSj3Ú‘ëB‰)***""\r" R"***(R†ÀéúÔTŒvŒâ«•ŸÌö 8î*¿™íJ­¸ãJ$ò¢ÒÉïš_3Ú«=ù¥2g“WÈÉjÅ3Ú3Ú ^)w(äš7dŞgµ9eP1ŠƒÍQÀ›÷çŠÑ@—~¥Ÿ9iÁÓÕAâ¿Ûõ­;’Ò-ùËJdœUA6zš™íWìĞr¢9Oj_3Ú«‡Å.õõ§ìûX“ŒRÕq2Š_9kE)***""\r" R"***(Ì°Š_3Ú«‰3Î(ó=ª•;ƒL´³c­/œµY%¨¥ó–­CÈÍ–D ôyÕ\JÈyÕJ Xó=¨c·ëP‘œRÕ¨Ø†‘dL¼
zºÍUŒS#¥_ ‹&eäb™æ{Teı)¬Ç5j|­“yÔå“ŸéUD¤t­8JÄâ¯‘ÈZó=¨ó=ª¶öõ£{zÓöh\¨³æ{P\væ«ooZPçœşJDæP£ÎZƒxô¥Ş=)***""\r" R"***(W)Vdâ@y”:Ô äf¿tUr"ZdË´õ§©\tÏ¥W”ğãš9	³,o_ZF“ÿ ×P‚GJF|÷æ©D,É<ÀO&€ÀœPOZPÄVŠ$¸–CàcyÕ `xïNS´ç(L²…9"% ªşg·ëJ­»µ"qêOæ`p(ó=ª)ò”›Ìö IÏ¥D­´c¾gµ5å' 0iD€Õ3Ú”HCV¢ÄÑlI‘()***""\r" R"***(@qÉ HFı+XÄ‹4Y¢¡ó=¨ó=ª¹J&¥A¨CäãàÄRq_3Ú•[qÆ*/3Ú•e äŠP&)***""\r" R"***(·µ=dU¨ ô¡Æ9¦‘-29hó—Ò ó=¨ó=ª¹C”°$)§œõ¨„˜=1CI‘×5j(9IiÁğ1Š¯æ{SÈÍW(ì‘8“×ŠBã°¨ÃƒÖ—zúÕ(¡şgµÇqLŞ¾´gµZ‚'”™\g"œw_Ìöıhó=¨ä‹-+€x§yÕU%=1Ú¼U(ŠÚ–7ŒRyÕL?„Ó¤õ­h£t>[–<Ïj¢¡V'‘NØşuj(—N²)***""\r" R"***(¼
_3Ú¢YŞ/™íNÈ›2q2Š_3Ú«ï”¢b{âš‚Ìµç-rÔò1Š@ÄUr’Ë>gµ`î* ù8Å8Õ	Fä¾gµgµGæ{R‡éÙ²¹IRN¼SÕ·v¨EZQ(=5å'¤/ƒŒTjwâ‚ø8ÅZ…ÄâL’|½*A2ã¥T`ô§‰23Ö¯†‹rÑç-Aæ{Qæ{U(ÊXó=©şrÕ@àõ©wCT …fMç-rÔ;Ç¡ 8' U(¢\I„ÀœKæ{T àäQÖšJãPL˜H3ƒN† S´ç¾g·ëZY©“dúÒ àšzúÒyÕI)2Ê bœ$µW3È§î)***""\r" R"***(Uš,È£$t5“”«&¥R‰›DâB?ıu'™íUÄœt ÉqUÊM®~XĞ89¦'½&O©®ËŸèó‘7˜=)***""\r" R"***(ƒp?Zˆ1$šppN)6Èr°à@<ŒÒî,p´Ú2Aâ¥™¹Q·©àÜ|§­FI=M*°ÍKwFnCè¦ï†•Ny¨nÄóV coQÒ›HX
—by‰AÈÍéQ‚qÔÓÁã¡©v!Ì™[nx§ÔHëOf¬¤e)ÓÃqPƒ¤çØÓò})***""\r" R"***(I›™*ıìš~G­@¤–5"}ïÂ“±.d©Œñ”àpsQä†œ„œäÔ=ÜÙ(`İ)j0H8ŒŸSQddå©%9\c¡Éõ4õû´˜™B´íÃÖ¡@Å<ŒÔ´ˆrDÈ@ÎMJ=VŒ“œÔáŠô¨hÆS¸şi¬Ã¤,M%+#&Àc9"Œ¡²2Š†…t=rh	ÀÊ2GCBĞÍÈ˜>:ÓÑÀ¨“œš’>ôI’o†œ­EGNV `ĞI ~>n´àr2*ãĞÓƒ8&¥Ä‰$É(¦‡ sšpäf•™‘*°\æ¼Œe&O¡¨h–ÉG4ğAïP9ç4ÿ 0{Ôµr2M.ñèj“súÓ·CRâÈh—Ì¦iwg½DK’:Vw%¤L„¦Q#šz°œÓå'bT?--1qK¼zÏTÌÉÀ R‡¡,sÁ4ªÃ¡?;"Z%·Ö¤·Ö §†)***""\r" R"***(Ò†®bKJj0Ny'ó§¡¨2dÁ8§«`Ô@àäÓƒŞ¡êCØ“xô¤Ş=)***""\r" R"***(0:Òo†¦ÈÊäë'¾~”æ’j })***""\r" R"***(99ÎM'$É²CJ¬ Á$w§õ&dë*‚iÁç5[x÷§+œdT8’Ò,î)***""\r" R"***(IŠ5XKZx‘p*HnÅ¤‘zOŞ*¢¹=	©2}MK‚1lœ0nôªpsP£ y=êBà3Pãs&L2)***""\r" R"***(8È£­VE/˜IùªyY“v,	ò)Ù¥WI½8J;QËs7-IÕ±Ö—Ì† ó}Í=c­KD=IQ×wz•Xg5_>•$rv&¥£)"Ò¸Ú)âTÀª¾gÖ•eç¯çY4AhH¦¤2)èj¢É‘×9Xõ¤5bÎñèhŞ=)***""\r" R"***(Aæ´hó}ÍO³FDû×ĞÓƒƒ€M@²Sƒ¹£†L¯¥J²©­¼‡ò¥Y<Æ¡ÁI]ÒPzçò§¤«ÜÕU—ßò¥O š‡É;ÄŠzRïZª²0iË)Ï&¡ÀÌ´² Í8¸Æj°Í(|ğ	¨q¹HŸÍOZPÀÔààQfdN­¶¥óô5U$=¿Zw˜sÈ©ä3–›–D™ùG­81J®’gŞı£øš—NÆ2,ÈÆx¡eÁ5¿¯4àÀœ
—)nYYu4õunAª¡ÊñŸÎœŒMfàÌeREÍêÇ Õe™ºÎ”9ìsøÔr¸´ZW súSÒEÆ3Òª¬µ"ÈzN(Í¦‹jãhÏ4¢@:UQ#Á§	3Ş—))***""\r" R"***(Ä©Í8>8ª‡Jxb:šBE¼QB¾;Ô>¦¹^sG ¹K~pşñüé<Õnı*¯™“×åq´{2ÄîêF)D©µz“FñèjãL‚1OJ]ÃÖ««g¥HŒOZ¥1ÅÏcJi…€8"ãĞÕ¨HA©^HªûÇ¡£ÌúÕ¨	«–7JP‡=sùÒï•j–™d8>ßZZ®’ß­;Ínæ­S6G¨¥VAÎjãĞÑ¼zµL	Äªz_0zUq Ïz<ÏöR…‚ÅãĞĞ%ÛÀªşo¹¥cÖ´PAbÊÊŞ¥óôªë&G?¥(“µJ™.%€À÷üéw r)***""\r" R"***(@²S·Š~ÌBÂ°#“FáëUüÁıêQ'¡ÍÌ\¥ àsJ²z}j ÜgwëFüëT¡rylZ2¯­0Ê­@fÁÀ¤ó}Íj 4‹Ç¡£xô5_Í÷4y¾æ«•‡)cÍ÷4y¾æ«ù¾æœ%ã¨§Ê¨œIŸâ?*È£©ªÊùèM9	9É«Œ”±æ)éJ€;Ó„¢Ÿ(¬Ë
ã S²=EVà)Û‰ïM@IäzŠ7»¿Zƒ'ÔĞŠj³,+1ş/ÎŸPaNó}Í_!)***""\r" R"***(“šnõô¦Grh­À¦ Éh0=éj>ér}MW*"Ì‘Ó“J\v¢Éõ4"…ŠÍCšZ…d#¯éNOBj•1X’€2y¦dúšŞ«9Q8 (¨„˜çğ Içó¦¢M‰F3É§îµqÅ.ñèkHÀ‡©?š´y©ëPo†€À÷«ä™?˜§Šrºç?Ö« Ó’NsšJ˜Ò-o†ãĞÕ7ÜÒ¤€œäô§Ê=I¼Áèië'©ÍC½}éwÑ¿ZN(I÷C@ ŒŠ…dP94á(ìM
 •ÉiQù¾æãªQ‰&ñèiAÈÍE¼zPÇj”KP&óz­bú‡,üèÜŞÿ j ‚ÌŸxô4â¡RsÔõ§ÑÊ!ïÒ™FIêh«QV"[Š†œ¬ÍÔÓ)U‚õ§d"T$õ4ê[=3K“êi”•“N¨2}M=XíÕ$.BJ)™>¦ŒŸST¬.T>¤¨C€1NËxşuVBq'	Å-EæzPùş/ÖšDòR‚É¨·SFãêjùA+"}ãĞÑ¼z‡'ÔÑ“êi¤®ÛÇ¡¥Ig5O©£'ÔÕògÍQĞÑæ-WVÇÓô5J Ñ>ñèhÜ§½A“ëO_»Z(\TL² àÀÔ"ôJ|¡ÊL
ØúÓ²=E@‡zJj$Y2LQFAã5õ£ÌõJÊL§œ“NŞ=)***""\r" R"***(@?ÅúÒäúš9ZTM¼z7CPäúšMÇÔÕr±ìO¼zO0zN,Z]ãĞÕ$ÄÕÉ7CNYTPï†€àñV¢.RÀ`yÍ.G¨ªàœpiAõ&©DB|QN‡¶>µ `{şu e=ÿ :| ãcòÙ‚1M¦ooZ7°äšİ¶¡üÌ}*š‹ÍÉàÒ†;†O-‰ËBmëëFõÏZˆ¸íH\œR½ÌÜÑ=j)***""\r" R"***(ÍëNYö¡¤g)Ñ’:ÍÏñ~”““PìCd ’q¸Ó‚õ°Òƒ‘œÔ6Cd½)ëĞ}*0Ê ¥HÀ5›Ô‡"}ëëKQ†ñÍ)s*dfä<pEH<Š€39§‚G"¡¤CdÈ½4ì‘ĞÔqdã&\
ƒ7;BIäÓĞœš€8î)êÛ{T´ÌÜÑ0 ò)j$sÚ”’y&•ŒÜÉ;šr8Îjr°ĞĞ¹É©á”µ¹ÇÊx§«Æy¤g)# 2jHß?yª¾æéûŠŒŠ—c)2rÀFõõ¨¼Ïj@Í[ëRfä‰·¯­×Ö£Ş¾´o_Zs$Ş¾´o_ZzúĞ\”XdL„äÓÃwSU£vçšHCJQ"R¹)| >Nˆ¸cÖ”EAë÷jA…^MA2x§ï_Z“%#"¤Å@$ìqÉ Í»–¡ °Ô+'sCKƒ×)***""\r" R"***(XMØ›zúÑ½}j/£~”	I8)***""\r" R"***(úRÑadÔıëëUC23JO=IoRÔn¹Î{SÃ2)***""\r" R"***(TWç
ië.;â§•™½Ë9ÁùZœ¬ äÕQ!=)***""\r" R"***(9[=MI›Ü³¼J<¨#NWéÏ5-äX^ij%”í4¢BO)***""\r" R"***(úRI±sØH#Šr2÷5eÇ&•_Ÿ”Óå3nåƒÆ•Nj/7ı¯Ò‘¥ÈÆsíYò™2Æõõ¥W]İj¨“ÒçµúRp¹œ´-;0)µÊ	Ájp`İ)***""\r" R"***(O!™2:š•J¯ñUA )***""\r" R"***(8L;œÑÈg-K[×ÖƒÎZ¬% ¥àuÅ´Ëÿ =YBšª%ÉÀoÒ”9úÔ:foBÖõõ§#¯MßJ¬²À4ğàµ7râå©.85E&#Œæ¥ƒĞT8™8“† äµ?ÌŞªÛ×Ö€àtj‡6š-+äƒ)Û×Öª¬™ëùÓ·¯­g$CZ7¯­Çf¨Q—9Í;zúÔY™µbÀ`FA¥àÕq ¥ŞİÍKW3jÅ¤“O5"¿¿5M$©V^ƒ?…'Û¹h8Ç&œ0zš¬²á@Î=©|ßö¿JË–®[ c5&õÎ3T–rx"ÈÚBe’@êhŞ¾µ“)jMàt5<¦REëëOF:Õu¿(p:5K‰”¶,o½=_=j°v<ƒNFô56V0’, ğjPÙû¦ªnoZrËïŠK™²Ú°“JOª‚BN~”øä#‚{ÔJ'<ËAˆèiU†95 —®)D¼}ïÒ¡Âæm´XY9À4ğëMUäõÍ;zúÔû6C‘j7^y§©ª¡È§ù¹ş*\¦RÔ°#ƒNW òj°”†4ÿ 7ı¯ÒSnZWR:Òï¡ª‚aÜÓ„€Ô8»–Õ•¾ñ§£Ud|´á!nCRä3–åÀAèh†«,¤uâ²+æ²•3"Â¶zõ§«`òj²¾9"Ëÿ …C´®»FM.õõªÊêFsNŞ¥À†‹A× f¥Ü§ŒÕ0ê{Óƒ‘K–Æ|¥¯0xÑæïTB-úR4£šj7%–7¯­×³UC.OZU˜çƒZªzÚ-ùƒûÆ0xÕo9¨æ«ÙØ’ÚÈ{œT‹'¾>•Q%¡Å=%àÓå%¢Îğzš7¯­W2ÔÑ½}i¨“fXŞ¾´n_Z€J¿J<ßFı+HÁ	Å“ùƒûÔ¢P;şu_Íÿ kô£Íÿ kô«öh\¥Å‘E^~õV½)”gƒT È²,y¿íQæï¯æÿ µúR«ää*Ô,…|wqNŞ¾µ°ûÂƒ/=JjÉ÷¯­( ÷ªşwû_¥(†­@¥­È£9£zúÕesÑ8HF­Ê‰Ä€t4¢\µ_Îÿ kô¥Îj¹¡h8Ç=hŞ¾µ]%ùG8¥Ñ¿J9ìYY28ÅH…OZ¬:
‘_û¦­A\–ÉX p)¥€êi/löéL.{VŠ(‹6M½}iC)8ÍA½½hŞŞ´ì>VXSúRşî««œüÆŒ3œÑ`å&Ş¾´ ‘ĞÔ[×Ö éT“).â;š<ÁıãQêhŞ¾µi!4J$çïSÖN98úU}ëëNWÀã¥R…É'SÃ.0MWzvæéò	¶ZŞ¹ÆiNz¨ôï´`àœSä%–7À4µ ”tëHeçü)¨‘"ÈlM;zúÕA)'¿J<ÜéOÙ¦IozúÑ½}j¨œ
_<·J¥Lvl³½qœÑ¼P	sG›ş×éT©“ÊXó÷(sÔ­æç€ß¥(vÏZ|‚jÅÀ˜Ò†_Z®cš_7ÅúU¨d[¸ö¥ª‹(4ñ/=j•2Z±bŠˆÌÄb›½»š¾@³'¥RšƒÌö£Ìö£|¬³½}hŞCUÖLJrHV¥Ê¶,¬€õ4»—®j )***""\r" R"***(oû_¥.Uqò¢}ëë@vjƒÍÿ kô¥3qM@-bÂ¿9İNÜ£©ªoû_¥(zÖŠHµ¼†—q=ÍWY@ÆMH%ãï~”ùHœ0=)***""\r" R"***(€8& ó}ÿ J<ßö¿J¥XŸzúÒ¬ƒ<µWóÚı)VPx&«–‹[×ÖëëUÄƒ³Rù¿í~”¹Ü.N€ij¸“Ã~”»›Ö©SKpsKUÕ›éK½½j¹ œ¬0j—®)D¼õı(äÅË…8ö¥óÚı(å&Ä•%A½z‘V¢¤ôÉ¨ŒÌF)»ÛÖ©@9K[×Ö€Êz«½½h0`	ëUÊ¥º*¿›ş×é@˜Éı)¨êO³eŠ	QŞ¡ƒĞQæ{VŠ!Éb]ëëJt)***""\r" R"***(P'§oZ¾Qò²Ò°ÀóOVpMUYqßğ§¬ .ªQd´XÜ¾µ uÀçµTöİúSÃ©jùY<¬±¹}iL‹T>g·ëK½}i¤„›×Ö€ÀœQ—_Zis×8ªQ¸Y“Òäúš­ç y?¥8H)***""\r" R"***(Z€r“äúšTÉêZ‰g9§o_Z|¬9t$ÀÆsúĞJ¯SQïŞ£zúÕ()&õõ£zúÔ{×ÖëëO”\„êË·­(`x Y àx`{Ñ`p%§+zµE¹‡z7·­4…È~[îcŞ’Š*›?Ğ¤*M?9-’åqû—Ö€Àô4Ê*LÛ†—¯Jjg‘NÁ=(¾†nB®Ü|ÔåÆ0´Êr&¥»’ä8c<šx*£¨ò=E(Çj†®K¥Îx4ñÈ¨éû—ÔTµbdÁˆèiõ
s“OŞŞµ3rD‹¤ÓÁd€35"ıîµ—"dû¢Ê;Ô{‡­( ô56hÆMCNBsQ¡ ò{S²=E#6ìLŒ¾´íëëQ!94ìZM\Îö½}iAİ÷y¨À$àz‚ NDŠ0 4d{şT'İnµ73æ$Râ¤,¤`€:|d“É¥kjCv%¤,SC
e	\Å»Ş¾´ ‚2*:TûÂªÈ›¢Š)‹˜t}éÕ$t4»ÛÖ“W%¾£‹ÔÒ‡Ààş•$õ§'İüi4¬O12HHëNWäÔ!€9R‡b:Ö|¦r&Ş¾´¢\éPooZ7·­±)***""\r" R"***(Ø°¯FsNŞ¾µ ëOÈõš3r$Ş¾´¨ÀÀñQdzŠPıƒTÙ˜œ0=)***""\r" R"***(-FĞ´»ÛÖ¦Ì‡-I€y§CPïoZUlõ4‰nå„ u4àAéPÇŞ†‹Ñ b:r°<ÍF­‘É£#×õ¡E2	ƒ0)***""\r" R"***(Îy¨ÃphŞŞ´8ØNÈ°’qN¤õ¨"¤Ü=jyQ›dÌÜği£ƒLŞŞ´o8¥k½‰·¯­×Ö¡V$ò~´úS7°ıëë@L¢TA2¶zšuB„äÔˆ@ÎM.RZ†œ	æ™‘ê)Üt£”ÎDÊÀ6	§†QÆjº¶iD‡ûßL¢e%r}ëëR\j®ö=èGSY¸™ò²Ğ`z¸Çª¬§4àÀK‹!¢päuõ§		èÕ
É´¹¿­CŠfrÜ°Œzçš_7ı¯Ò«†£Rï=A¨pFmu,«ƒÖœ$£Uu8µ.â:*ÍÀ†ËyÎhÀj¬’~ííšS'bÀvîié'b
®’:z°4¹Lš,‡Ú½x£Íÿ kô¨0ã4=ê}™Ÿ+,=ù©c—¶j²¹Ç"¡©p@Õ‹&O›Å; ğ)***""\r" R"***(V{ÓÕöğ+7™H°¤“NÜ1œÕa'=)âLZ—	nXF\õ§	 èj¯™şÕ*¾G5ÊZ—@y-K½}j¢¶ßâ©w“Ñ©rKbpGPiêÀŒ’*§˜OF»ÏsIÂæRØ/§‡R3š«™'ó©pj9,e"mëëJ²Æj ç½;põ¥ÊÈh³æöİK½½j¶HèiÛÎsŠ|„5bq Î)***""\r" R"***(80ÎAªÁòqŠz¹^”œ›E¨Øn?Zy*9Z¬’nêE;#ÔT8#)"pıH„s“UCwSR$‡¨©pFM\´¯ıãK¹Oz‰=XRäzŠÍÀ‚`ÄSÖ\¿…Wc¸§†g?­G"!–ô¢QĞœÔ˜p)***""\r" R"***(Ïz‡Z-_Zz¹OÒ©«ò~• ´½™“EƒpGšfàÔ>g·ëI½½j•2ynN%ÉÀoÒœ®AÉëëU–F4á+Š¸ÄN%Ÿ7ı¯Òœ²Ş«‡#¯4ªÛ1WÊC‰`HCR$£jª¶ŞÔààõâŸ#‹>oû_¥8H¤g5S#ûÔ¡ñÑ©û2YozúĞX¦ª‡nÍJdb*Ô	jåëëFõõª¾aÎ3O`}ê¾DKV,¡§ï_Zª²ç?J“Ì?ŞùPš&Ş¾´ ä‡Ì?Ş+FOJ$»X²²dzûÒï_Z€àÒù‡ûÂ«’`A<z3“U·±<5ÛÖ©Dve­ëëFõõ¨2CJŠÕDh˜2óÍ*¹Ç¢§,˜ã"R,É—îÓ€y5ÉÇQJMDI2ÂÉèsO†«uğäu«åD¥€êhŞ¾µÉü©›Îx5I
Å­ëëFõõª»ÛÖ•\“Œ~5\¢,ï_Z€ƒúU|ïPÅO”i2ÈúRïoZe#¦)D¬jÔfN®1ó]ëëPyŸí
_0ÿ z¯”’`ËœOV rj r½y¥TuÅ
,M\ŸzúÒù¸ş/Ò ó}Åaşğ«P&ÄşfxİN;1ÅVŞŞ´üQT¢KW$Š]íëQÜRïoZ¥&S‘É£zúÔ;ÛÖíëUÊ+o_Z€t5öõ¥VÏSV¢€°²+æ—zúÔ ƒĞÒ†#¡ªöh—mëëNW=Aâ«ïoZ7·­‚å,—' Å&öõ¨Cärijù<¤ÁÈëÍ<9jcéš9y§Ê…ÊLÒ…¿J@ê9Í2Š,‡dH%ÉÀoÒ—{zÔ[°x"”Éî*”
Jä›ÛÖ€äu˜¼)QóÕ…>D;X”8=x§=ª,QEO%™/R]ÍëN;·éUË@`ER‚bäl±½}iU>SÅ@$Ç Šr¶G$Ur É··­80#­Aœ÷Í.æèå°ùKQĞšœñQn´¾aşğ«IbMíëJ¯Øşu˜¼(ó÷¨²‘8a)***""\r" R"***(9\çæ5]Y‹`šu
*âåDâE¤µUBäö©Pœš¾På'GCHe#©ı)ˆèi	'­¦n‚_ÒHÎEAE;"KJË·­.åõªêF94£¡£nXöİOÜ¹Æjº‘ÈéJ¡¢Ö!9a)***""\r" R"***(7{zş•sÚíëUÊÆ ‰7·­*–$Q9äÓ÷«Q)&åèÜ¾´ÊG$c|¨	D€t4¦Q*¾öõ¥VÏŞ5i!X›Íÿ kô£Íÿ kô¨·/¨¥È=)***""\r" R"***(W-ÇbQ!<ç"®Bà*€33NVã“W‡-É¼ÃëúSÖBGôªôõ#‘Ò¨RÄn}iÌç…WG^h.zçÔC”—Ì=…&öõ¨Ì™È¤ÈõqŠ(cM88)***""\r" R"***(@K¼W`å,¤ÿ Zx†«+`dÔålõ4XJ…ï]ëëPn7~´d†šErï_Z7¯­A;ÒdzŠ¥‹”³O uª¢eÇ\ş4¢Q)***""\r" R"***(>F¬¶ãƒFöõ¨€9§«c¡¥Éb\OËê)¥ı7'Ö°?¼œ¬?#ÔRÔtdúĞK›$Èõ£ ô5(;NOz\È†ÉcïOW¥B¥ûñR+ƒ÷MCfršœœš ÉÅ>¦ŒŸSSÌG:M; {S‘N^”_]¥6¢•Fî„QFHèhm‹“FAÎ)***""\r" R"***(:£É)***""\r" R"***()AY±sE?#ÔT˜÷¥RÄàµI.I“dd`Òƒ´äTk…9¥.OÊH“Ì'¦)ÊKu
u©Ò“3r'¢£IIéÏÖ—yô6lk¡ã“Ş¥VäÕubFiÁˆ9ÍC‰.I–0))ŠçoJ7ŸAG)‹&R1ÖŸz®$#¯éR£¥+2&9Ï'4ÜQM,OzJZ7rLZUûÕ89§+’q@‰²CEDÌTdP²18&›MäL ¦† )***""\r" R"***(FŠr±n´ˆs¸´gE5œƒŠM\–ÅÈõ"‘·­C¼ú
ŸJ\¤Ü›#ÔR‚;ŒŒÒ«©!²|ƒĞÑQä†”¹#Rµ÷2nÃ²=E9ÎsQR¡94˜µh°„dÓ²=E@‚)ÛÏ¥ID¹¢— ô¨U‰84ğÅzUYn.bÊÏ4¹¢ G<ñK¼ú
Vd“dzŠ\Æ¡{Óî)***""\r" R"***(>Q6Ñ(r)Êr3š„9¢Cÿ ê©"í–wQKP	)D§ø.FE™g#ÔQ‘ê*ÄsšÙ8Å.S6™>G¨§!ç¯ lğiÁˆ¤âÌÚhŸ#ÔQ‘ê*çĞQ¼ú
\ŒDÙ¢‡ÔÔ ƒĞÓƒß?Z—KdÙ¢ŒQQo=ÅÎxr²ÄÀÆµæ²+3) bœc­C¼ú
x9¨å!»FG<Óª¸$t4á+gš—&N§´ìQP³Ú‘d;¸¥ÈÈeŒQNCÎ	¨7ñÓšrHsøVn:™·bÀ%NE9[=qP¤‡8Ïj]çĞVnÒ‰1ßõ¨ƒ–dÑIÅ37æN†®r5´àäTrØÍ»”ŒrirCP+½)àœdRå3¹8#š|dsÍVØ¥Y9©äÕrz`d™±œÒ,§84¹L$™ae=Í=dÉê*±riD„u©pF2¹kpõ¥V#¡ª¾iìÆœ²0èzÔ¸XÂW,«g®*E|ç&ª¬„ôıişo¹©ä2’,ŒÓĞ’95Ueb84¢Fvö¤àd÷- ğEH²|½ªªÉiáÎ?Æ¡ÀÈ´œŠZª%#­H%b2)***""\r" R"***(O#&E¬Z2=jºHOZq“.S);)Óò=EUŞ}8JÀóIÄÈ² Òù¾â«	²qŠPäv¥Ê&ZIëR$‡¾*¬d§µHµ.73jåÅlt£Í÷XL@ÆMµO!“‰gÍ÷õnâª	Iœ³2ÒtÄÖ…ås´qFóè*°¸8âæ±ïPéíĞœÔæ¤WÅTó_Öœ“àÒtÑ-\´_Óõ¤Ş}Aæ·­(	4r¡6óè)É'5bZQ zĞ 'b}çĞR«œóÅWó[±£ÍZµn‹BB)***""\r" R"***(RU5Ÿ­J’œ*”Z&Z“äzŠ2CPï>”yŒ:U(ÜVNŠ]çĞT"l”'j”Iqd£$õÅ<`qšƒ'ÔÒ‡#µR‰-–T(èij°—	§ù¯ëOVM@$t5šİÍ/›îjã å,+:şTá‚y5Ye9àştï5ıj¹q³,€ ä5.G¨ª¾kúÒ¬Äu«Pi[)wŸAP#±ïNÉõ5~Ì	wœò)Êëœæ E.óè(åBjåÀŒç¡‡cU„¼u?…89Å5r²Ğ#šw™2*§šŞ´ÿ 1½)¨k“ÏSúÑ•õqèhŞ}W(ÔI²=E&à9ò¨·ŸAFóè)¨;…‰‡4+äóQï>‚çĞVŠ,!óNÈëš«æ0éNY	ÿ ëÕ¨Í3àğEC×ùTE‰¡[hÆ)¨Ü†Ë-?~G'ó5THsOY?Æ­E	¦‰ò=Eµóè(Y22ERˆ­rÖGLÑ‘ëPdç9§Õ(“ÊHúÒù¾â¢¢­@’_0ûQæj[­.óØSTî›Ï ¡_=H¨÷ŸAI¼úSö`YBriÙ¢«‡-Ğš\ŸST¢KLŸ#ÔQ‘ëP‡À÷£Ìj®@å&¥``Py¯ëG˜;Š®Q8–ƒzÖ¤Èõªa2)***""\r" R"***(JúÑÊ'Ç›î(2g¸¨¨'4r!YdÖŠ‡Ì ñA•ÏZ¥ÔI²=E€èß­C¼ú
U,zŠ|£²&}sOÜqË~µ_$t4¡È£SdÙ´¹¢¡Ş{ŠPAùZ+–Ä ŒğiC1QR‡"šB%W$Ô‰î?¯¼ú
Q)îMRŠ`YÈíEB²ÿ Ö©7ŸAUÊ€u*Ÿ›šfóè)7ŸAG(2Â»­?#ÔUQ#
U‘‰Á4¹H¶¥œQNFõoÖ«¡$òiáŠôªQVXÔQæûŠ…H=(f àUr´&‘.ìœƒùRäúš…NFir}håd4‰ÔŒriwï~µ ‘±JÔSå'‘“ï4ñœñP+œJQ+Š9Jå±k#ÖŒQU|×õ§+±ÍZˆrØŸ#ÔR«`ä‡yôõÔEb7ÜR)***""\r" R"***(ÔŠˆ¸9¤ó=ª¹GfMz*$—oQNîè*’wV>œ„É¨‹Ş“-ëWf¥ŒQFG¨¨“îÒÕ%aò’nŞıiDƒ¡¨€'¥8&Š©+‡)8“±#ğ¥/ ¨sh3Œpµj"å$¢¡ó”<×¥W(r’ÑøÓ2}M>¦­D9IPíçwëR/=Xşu]	'“Úş½>Qò“Ğ¨Ã–èMÒ@¢HXœŠ*:PäU¤„à‡ã9§ ¸ÎïÖ˜§#4µIÊH¡©#ãU|‘ĞÔ€‘ĞÓqŠgæR1ÀÈ¯3˜şårŠb‚[$~4ğ èåCfnV
r:´ÚTëøVmçqôèûÓhÉj’´Í´ãÒÄı)( Í¶Ç§İ(è*l¸üjU$¨&“‘Š(¥Ì+´=[wjZCÀ8İíëI»‰È}*}áQ†rx§ ùäÒ'™ÑQƒƒ‘J7 ÎR¸út}ê5R5"‚ÈíNÚ\Í²DïN¦Æ<Ràz
F|ÂÓÓîŠf è)é÷jZw$Oº)j:zôJ’… ‚¤¨éŞg·ëA›wE4¸ì(ó=¨#™O¼)ààäT>gµ(Ÿ—XNJÄ½i;ş>ƒó§GœóéA›jÄ±÷§TtwÅ'±BJ*:2GCR•Èl’Š'9Í.æ=è±<ÃéëĞ}* øÅ9X‘Ş¥¦Km’T•qßŠu.S2JTûÂ¢¥E NO{Tk/AŸÂ­¸ô¨q%¡É×ğ§Ó¶ö¥ó=©­	$½:¡ó=¨ó=¨%ÜšŠ‰NáœS•öŒcõ —¡2}ÑKQ«œdqK½½iY™/Aô¥<P‡ã¥8?ıTÃ˜’zĞ½GÖ›æ{Pdô’±›DÔw¨7µ804¹LŞÄ´TtQÊA(r:óOà5W§,„M'5¡)m§¥.ıã®E@\ö§!$dšTg+¢PH9õ$¨É¨w7­/™¢—)›W&”á'Š®$­;'¶)8Ë ‘Ó½ àæ¢Yqß¤’y¨å2jäÁòqŠu@¤ƒ€j@Ä}=)5b	“$ )j/3¾”yÍéPÓ¹”•Ù0r)Ûª¸`Ç­<9j9nCE„$ç&œI'$Ô 4¥Æx©åîfÑ`?­=ÎsU¥89KÉ¢Ò·pië&*¢ÈÄN;ñIÀ†‹‚N:P‹úÕ`íÁ¤IsÔRå!¦‰è'™íAsG-Ì›&¢ ŞÔ¾gµ.FfÙ>ãŒfŸûUU•ö§«sê)8ó,ùÔğäpj¨”9eÈõ¥ÈdÕË`ƒÈ§+ö5PLGõ¿K›E {ƒNIëùÕPäŒ†§‰IcSÈe-‹^fGLş4å“ÕT;qƒOIr:T¸ÉÕ³Oó=ªªIÇOÖœ\v™=ËgµgµWó=¨ó=¨äb,†ã<úSƒ‘U¤tô˜ö©ä%–ÒA)àƒÒ©ùíÓô˜ôÍO#3v-‡#¯4¾gµWY89¥óš—#fMjXV'‘OØşuXI‘Ò—Ìö¨äd²Ò·piÁÇz¨³Â®·ãIÓfm"Ğäf€HéUÃ¿µH²’9¨äd)CU÷·­ÛÖšƒ"Ì³æ{S–N€Âª‡Å9dÀ?…W³b”0ÃúÔgµ
ûš€¬‹R:
zËŸz­ÏzrzšµL–Xó=©é ÇÕn”àç¸«äB,äR—ªºœŒâ£‘'™í@pzñQùÔyÕJ²'BsJ\vÊZ™íZFå$ó=©CQÈÆ)UÈ‰qH°¥/™íP¤½éNó=¨å%¤J²p)ÁÈëÍB­¸ãàÄp)***""\r" R"***(RˆœU‰Ä„ôj]íëP£&–´²‰2¿1§"«ÒîoZ9upHéR) g=ª°˜÷5"KhäbjäâN9«.:œTBAiCƒÖšƒ&Ì”’zÑP—àQæcµh .YQQyÍéJ%'ŒóG Y’T‹Ğ}*)***""\r" R"***(íëFöõ«ŒlÆÓDôTÛÖœ„œäÕò’Éh¨èƒ‘NÈ‚TûÂ¦Oº*°sÜ~4á/ûTÜ.KL±EA½ºæ9Ô	$”ï3Ú£ó=¨ó=ªÔ;×$“ŒSª3¶?Z<Ïj¥ ³'ÜÃL2rx¨÷ÙüéU³Æ+E	Ä™íJ­»µ2•[oj9u‘ r:óKæ{T~gµgµRˆ¹I<ÏoÖœ¬q‘Q)Ü3Šz¾8#ñ¢ÁÊJ§+KQƒ‘hªå$”:x$t5 CÔxb¼ÑËp±bŠ‹ÎjU˜¦Ÿ-‡f‰(¦ùÔ&zU!j>—sõ“”yÕv¸ìÉ©¶•$õ ¶ÑŒş”(;&‡ùÔårG™í@“ŸJ¾FQ>öõ§•
¸#ŸÎ»pëÅ5m©%
JŒQÓ‚°‡ÙGCRUpHèiŞgµ>D)***""\r" R"***(RƒƒšƒÌö¥I>n”rØV,ÉÆ)j3Ú3ÚV+2päRùÕ_Ìö¥I@ê)ò0³-#¯4¾gµWYÿ »NY†jùY.,›Ìö¥#5’FM=Xüi4.R@øÅgµ0¸Çgµ
#älœ;c­›Ö¡Y1íR+níV¢#üÏjœğ)½Mj6).öõ 3Á¨©Tàæı˜ó×š)²qŠZ\¡ÈÇ #9åm½ª*UlU(‡)#Ç8¤ƒ‘Mó=¨3Èªå*Ì™	À9§©ÊÔHã ~´àArŠÖ$¢š¤ŞŞµj$òÜxŒE7Ìö ¾F1Z¨Ù :ŠŠµ%O¼)õ b>”¾gµ>Qr¶MNG^jq=)Şgµ5BÚ†#¡£{zÔ*Ù¥ªä!.öõ£{zÔTAÈªQBu$®M($r*!Ç#4«&)***""\r" R"***(>EaY‰8äS#¥B$ã¥aÎqBˆ¹OÌ²÷£kg“úÓ<ßsG›îkÇ?µœÉ}…*16;R¬¹à*\Œœ¯°úPàu•3xô4åe'ŸJ›“{==A9Ü?:Ì†ŸæÀÅ+¡6 <RPyêOç@àæ¥»“Ì‡ ã§4ğÀQ‰=Jp9¤Cc·CN#5(b)¦O3$ù­8€p?*j±^”…É?áHÍÈPI#Sê:r±'ìfØõô§àuÅ09£qõ¤Kvzâ„œäÔhI<ÔàHéA-Üš>ôê‹ÍÀÀ£Í÷4Èr%¥
ÄdˆMÛùÓÒ^œÒå}I¹ jEè>•bœ&ÀÆ)5a]QøS„Œâœ²`qúĞ•ÌÛCŠ3H9#ëAf=é2?¼?
FwD˜‚—Ò¢ó}Í(ä`şf‚.IFHèi›Ï £yô™¡'94½ÿ 
‹ÌnÔá(‚\•‰(¨üÿ jS.=(3nãè¨üÿ jQ!#8 CèÉõ¦o>‚çĞQ`'©*|u¥ó}ÍMˆnä´T^o¹ MZ‘ ç8§ûÔ+9ÇZ_7ÜÔµvC½Ér}M>¦£p	§«ÖšVôÏ9ÏãN¦‰=hŞ=)***""\r" R"***(D\‘:~4ê[#‚iC0ç4È“&Oº)j!&SG›îjw"è–¤ªâLÿ çN6rh³Œš‘i†AM2±ïME’<±'9¥F9¡ó1ÎGçJ²óœşµMhKdù>¦ŒŸSQy¾æ4„Ôò’L­´àsØÔlqO9?•.VKd´d†£OBiC61šV!ÚÃò}M=~íBƒœÓ„˜M2ZPÄT"lzÓ„„Œâ‹"$Ñ=8©ìÇó¨VoZ_´ñšC	üê3Ö”HIÆMEæ·sKæ¼Ô¸N¬sŠV`¢¡Yy¦BGüjyH‘*¾O©‰ëU‘‰5'˜Ã¥O&¦M¤Ë÷¡˜ƒŠge¦~3Ö§Í²a!ŸÒŒXMWîŸ‘ƒšN;t,dúÒ†#½Deã9¤sÔÔò3&Ë œu§«g‘UDìG“pM'7"ÉfïÅ!b;š‰®=é¢bÇ­%&ìO“êiË»=ê69f'4¹Û&§!>µ›õ¥Ip	üir3	jX§GŞ«‰O©ü)âcØÒåfm2z" 3qšrËÿ ­K‰å•bGZPÄæ YO®iûÉjyLÚ'V`3Õ 'WÍaR$ÄI¨å2h²‚Tô§'½W^¼ÓÚ^zşU<º˜´J	ÈæŸUÄ¸<5;Îoï~´œY$Ô{ÔK3ÍfOR)r2dL»‰á¿Z~Hèjšp”÷&—³fm;–³Ó4íÍëUÄÇ±ÅqşğüéòÓ,«°àpfêMU7¯åR,£i8ÓE•9§"«‰ÏLÓ„™?{õ¨p3-+)à‘ĞÕQ+ôõ¸5›.Ì°Xô™>¦¢2ûšO5ıi¨‘6O©§#UüÖîiË._ÎŸ 8–2}M9d=ê·Ú)***""\r" R"***(*ÌOSúÕ(4KH´·B:z1=êªLV4õœ„ÓPd²ÎãëJwªßh4¢Rz“G#Œ³æÓ4¡‰ÉªÂnpçOq÷©¨ŠÊäÙ>¦ŒŸSPùÃ»S„Øÿ ëÖŠ,l±JK¤ÔK8†¡§ÍW+$”9iÁÁ8ªşo9É¥YNx&…q5rÊ}áOªË3É§yÇûÃó«Q'•“Œ†•[sP	½[õ¥ó‡÷¿Z¥.RÂ¶zS²}MWR‰Ë*ùJKBpäRï>‚ æ—ÎÇj¥IÔäf¤VÅVó‡÷çKæóÔÕ{2Z-‡§Ua/“N4r2Iè¨L¯´y­ÜÕr5(8ì*7ÜÒ‰±Úš¦;2]ÇÖ•	'Ô>µh#¥W!-)U‚õªßh4ñ+w?•Z€¹KÇ¡£xô5_Í÷4iÏZ|Ê‘gxô4 äf«y§ûÆ”\1Í5'n…Œ‘ÜÓ„3UÄ®FsJ%÷5j$4™k,zOªÑÜãŒÓÁÍW)6±=Ú½h>ôÔXšU)***""\r" R"***(@·óN•J-Ó'ïKP‚N3Kç7÷…>PådÔTBbG?¥o¹§ÊÊP'V `ÓÈÍVó}Í8Lq÷©ò0±i>è¥ªâàâ”NOñ~´r’âîO“ëKóæ ó÷‡çN‘Üş5JådÅ\îıi09ÍGçïÎ“9ßúÕò
ÄŞkúÒ†fêj3ıªU”ôı˜XŠ‹Í¡4y ô&Ÿ(dúšBIêj/8{õ¥óÁéT¢ÇfÉ(¨Ìã°¥gÓñªQl9Y2}ÑOW b«‰Èà@•z9ZÜj%ãĞÑæûš¯æıiDŞ¢©D|¨³“êiõYfŒÔpşñüéò\\¤´T^pşñüé<åş÷ëK9Y8r:Ó·CUÄã¥o¹§È>TXŞ=)***""\r" R"***(ƒt¨UÆrNx§†ô4ùt)23‘N†¢œr*<ßsG+Rt“dõ§=súÕo7ÜÒ¬ädıM¢i×‘šZ®.:Ó„Ìhåb&©CÒ«lg4ñ'=OãM!ò²Íœ;5/›îj¹Xr²Z*!.zS6j”ÔY&Hèiw7­Cæûš<ßsT Šä&›¡ıiàc¹¨VLåNd}ê|¢äÔ’ŠˆÉâ?…(›ª”GÈL¬ Á¥/´uüª?Úœ$\gš¥r“	NxÑ¹95˜LÒ†=sT¢¨—-êiõ
ÈÀÓ¼ÿ jµr²J*36{Ry¾æ©E‹•’ÑQyÜcš<ßsV¢ÁD™Hš]ãÒ óObiË*µ\¬j$ÛñØÑæûšÎc&“zZ¥å%ó}Í(ryÍE¼zU—Ö«”\¬NFij!/M<H˜å¨H\„ÃŠ*?0tİNóÖ…(Ÿ˜åÆ8Í '#šBA<
:s_9Ìd¶IBœ6i›ÛÖ‚íI´È•Ÿ#ŒĞ®A¨··­*±'“KVKh˜9=	§£íô¨#¡§¬˜ëÅ4»’ÚèJX­úĞ„ÔEÁêhÀ?¥=ÛdÁˆïOV%FåP'œÓ–\(çÔœnG3%Éõ4àãæ¡óÚı(óÚı)Y‰ÈŸÍ÷4¹níP#¯4ÿ 7ı¯ÒšVÜ†Ñ&O©¥EEæÿ µúP$$à7éMÚÄ¶XHÉ4dúš9;RïoZƒ&İÉUÈ<š_7	¨„u4		èh3,-Ğš2}M1[oj“ÓŠ	r$AÉ&œ²sš‡{zÓœg4jÈl²¬võ¥Gz…e;FM(RåDs‰0:š]ÄZˆ:ã“N.@¤Ñ-“4³ŸÆš	,9¨ËœûSƒ.F=ªL[%¢£2àà·é@—<gŸ\SDİîoZ7Z{zÒ«y5VD·qÙ>¦œ„œäÓh”šÔ‡rJ)›ÛÖíëG+&ãèÉõ¦lòh.Hàb–¨\Ãò}M88Ç9¦äÒFi2$Üı³Fæïš`r:óAs(&ì~æ÷üéQ‰`j=íëJ²yüéYÙ:}áOªë>)***""\r" R"***(šwÚ}ér“tM’:p—N>•\\p)Ë!<Ô$'$ZVÀ$š7CPù¾ÿ ¥oû_¥4¬dİÙa[#‚hÉõ5ÉjpryÍM›d6ÇäúšPÄw¦‡çjnöìiò°º%Ş=)Ù>¦ G^iâBÃ­+1;tdÁÆãG›îj2ÀqšMùãm4š%´‰C‚p/B¨óhdıìŸ¥-Yœ¤‰2}M9	'“Ú¢ŞŞ´å“h³!È–”1^•†—y¥fKd¾c”¢SÜš‡{zÒ«ñóVD¶L‘œš]ÌF* çr¸Ç&¥¦fä‡†#½<1Àæ¡ó=(™€ÀY™¹&K“ëRTÏzy“ªjæM’¬ƒ¦søÒ‡=ê ë¿N)L¸8-úTØÉÉÜœ8Ío¹¨DÃóGšR\Ë/òíNóG©ªë&:Òù¿í~•.&m¢Ò¶$Ğ_ĞT+7Ğ%ç¯éSÊÌ¤Ùaã4ñ'ê·œTz
>ĞO Òå2æe“6O'¹¨<ß|~y¿í~•<¬—$Ë/¿çOóyêjªÉŸzzËôr²[V- SLÄ*?7<nı) pM.SN³ç©ıiêäæ«ƒ‘OYH?Ê—)›W,y¾æ7ÜÔwû_¥9±äö©qHÏbÂËïùR‡bx5 $t4å‘–¥¡7¡`?­*ÉÎWÔâœ²“óúTr™H´²@ÍJ¬vjšÌsœÔË3m.&M»“îoZUr:“P	zpr:óRÑ›-«wëJY‰ëP$ÄSŒŞ†¥ÁÜÍ­I2}M9\ñ¨<æ¥óÚı)ò¶Ë
ùç?.ãëUÖ`É§yÍO”—bu¿¥/›îj¸˜÷4ííëG)-î'£~´¡zÔ+&:ñJ%ç¯éK†‰ÖCÒ®1Éæ ;Ò‰;ı*\,²$lt§,æ«‰˜S„„ô5´Y¸§¬ÀöªË!#ƒúS÷¯­G!“HŸÎŞ?7í'8¨œñ@fÏ&©@I$X±8¥Y3P	æ²©<uªTÁÜXƒÉ¥ r)***""\r" R"***(Bf#¡¤É5\ŒÍìYOBièÄæª‹€:T‰p@æF%Æâ;Ò‰ş•_í>ô	ÉäQÊÁÄ´®zçó¥.Oÿ Z«­ÁÆ?ÎzRäw‰CŞœ$Àêj7ı¯Ò”L¸æ©E‰]09Í;Í÷5_ÎoJ_7ı¯ÒµPb³'ó×ó§	Ob*·›ş×é@›9ı)ò	Ä´%lòiÂBN5Yn3Öœ'¥5+2|ŸSNBNrj9=éË1ìi¨ŠÌ°¬sNó éšef»ÛÖ­D9Y)•³Á§+1ÍWØ&¤Yzşj"i†#ÿ ¯OIqÇó¨KÂ9ïUdfÑhKÇz~óéU•Î9 ˜g“NÂ²%ó_Ö5ıj#2ôoû_¥>P²&ó_Ö+g“Pù¿í~”y¿í~”ÔXÉüßsG›îj7ı¯Ò”K“×5\„Y“	€ÿ ëÔ‚Vî*®wâœ²çŞ©GAò²o7ÜÒ‰±Ú¡ó=©CôùDâÉ„™9ªâP;ÓÖa´a©r’âÉƒK¼zT>oû_¥'œÕJ$ò´Xÿ ^”ÍƒŠ€I{Ğ\çŠ¥Iu'óı¨dã\ÈGVı)VBH9ªQhm+Cœò)|À:f äàÒ”¹M4‰&ó}Ío¹¨<ßö¿JQ!<†ªQ2ÊËïùRù¾æ (Ï4y¿í~•¢‰6dşo¹¥Y2zŸÆ«‰—¡9¥È£YhIÇzPÄŒäÔp1‘KöŸzj,|¤áˆ§¬¾ÿ V±å“<õ«Q¸íbÁc×4Ñ/8Ôfci¾xíT¢KEŒŸSI¸úš‡í>ôŒŸåUÊ+äúš2}MCç5cŞ—+‘:¶:æ”8ÆsŠƒÍÿ kô Ì;j(–<ÁıãIæsÔÔoû_¥(sšµÊ‹\Òù;Ô+/AŸÂ•¤Àô§Ê™6Ô›Í÷4¢\ñªşoû_¥(võªQĞ¥Ğp{â”ÍƒŠ€HOCFöõ§Ë`H°³pE;xô5X9iÂRN~”¹GÊ‰Ã‚xÍ83õÈAüéÆcØÑÊÄâL$#ÿ ­OYtjª&=Í=&#¡£RÒJÄ`Ó·ŸAU£™±Nóš— ¹Q1séNWŠ¯ç59fç´ùl.DË*àSƒ š€L;Šp˜ãŠ,Á@°%ã©¥gøãPb3šUoïn_!?ƒúR‰[¹¨7¯­/›ş×éZ(”±æïÈ&«ù¿í~”«&G­ZAÊOæ´hó÷A½½iU‰<š|¡Ê‹	&?‹ò§	2>õ@	)***""\r" R"***(›Öšˆr“1üFœ²8ıj¾öõ§,˜qO”vDşaì)ÊÇoZ®%ç¯éO0RLM‡=éD¾æ óÚı)w±ïM"Z'gøãCKÏ_Ê¢Ş¾´P:Ö‰”“Í÷4y¾æ¡ó–9j¬>Ba&N2iÙ>¦ YA ÎçµúU­räúšT$ç&£YëùÒ‰ èJ[°å±<}éÕKÇZ_7ı¯Ò© $¢£óÚı)C“È4ùX¬‰“îŠZ‰e;y8¥Àj9Xí¡&O­<8?ız‡{zÓ·¯­W-Åd~hQÓ­3Íô"‚äŒWÉì^s!YÆ84››Ö’”:Ö‹Ü‡ ËûşTåfÏLqMŞ}Ï ªLvI¹ÏOåN]ßÄj5“?Z‘\vl\âÑÎzQz(ÑœPÄ…8Œâ™NW `Š!É¢›¼zQ ©İtKE08ş!NÜ=i&ºä…¥O¼)›Ç¡¥WàQ¡.H”RïoZb¹'¥€¥§R…$´èûÓƒÿ ×¥VÇLUY"‰“œšuD’ :ştï7ÜP–†rúPÄp)***""\r" R"***(GæÓålÔšFnDŠI\š‘T}ª5#oZp“‰lîiÅ×Ö¢YëúS•uæ‘V$¢šeQIæûŠVD9¥O¼*?7ÜS–P9¤“!^ä´GJ‹í½(˜ŸJoa·¡.öõ¥BNsQy„ôÅ=$ÈÅ	2[v$¦³0lM3bšÓr1LÌxvy¥.{
ŒHiCŞ7aÁÏzx—¿¥B\çŠúŠ9I»'ŞŞ´oaŞ£ŒJä`
VB¸ÿ 7ı¯Ò7'¿J€psE“'™“+18Í:¢Gç§4íçĞQÊ„äÙ"uü*EPİjR	Õ{Ó°®H)***""\r" R"***(>¦š&{ÑæûŠ›jCz’+ïOWb8â gÒ²qÛñ§Ê‰l”¹Å'˜}OåLó1ÜP²ç­36ØúpfW4ÍÃÖ$õ©å“C¨¤,1ÁİçĞRµ˜œ‡Ò§Şóè)V\rEÍ²j*??Ú1' R&è:rsšb±læœ¬ éÍK½Ää¬?8æŒ–9ÏåL''4Û×¥3r$@À4å$ŒšŒH½@Í9d$p.Vc)¢™¼ú
_0½G+3»&'4wëQ¬Å"œ_ĞPÑ-8Ç4ÒŞHÎHÆ))¶9Y‹`šp$t¨Á äRï>‚ƒ92MíëJ„œäÓƒJ/B)Ù¢±*3“J_Ò£Ş=)7ŸAJÄ¶Iæã‚9§+†úúTsÉ4ªØ÷¹Lİ‰Ä˜ã4»Ø÷¨ñÀüéDÄqŠN&L²9¡ÈëP¬àNó}ÅKD6Ë!Ïq@“•œ s‘š\¨Í»–„¹8)***""\r" R"***(úS•˜MV rqR$Ã¯œY)***""\r" R"***(“Ó‘Èã5Úµ(›>•7%ù–w“Ñ©	'­F²Óõ¥ó}Å.]İ‘ b)é ¨<ßq@“Ô¹Ive À÷çÒœŠ®“ÅH’äv©q!²ÀvÀæ¤I8çš®$ã¨¥×ô¤àbİËJÿ İ4»ÛÖ¡I‡zw›î)r½É7œQ½½j3.=)àœQÈCDË&:ştï7ı¯Ò äPeˆ¡A™´îOæÿ µúSÖ\{U_0˜§¬€õèåĞ’Ú¶îÔµ
\`sNgÓñ©qa{†#¡§)%rj7ÜS–p(åv%²`Ät4«#)æ¢óT)***""\r" R"***(a=1B¦fÙ`K»¥<L{Õ]çÒ¤u=@¤àfÒ±9sÚíëQÔŸhÔ¹È›{zÒ«1lP‰óOI9Í5)***""\r" R"***($K@$t4Ï7ÜP%È¦âM®L­ÔàØÍB’Ø§y£ÚQr«’ooZUq˜Ô->ßJAp:SQH²$ì)***""\r" R"***(=e `ŸÒª‰sOYxíøÓäFåíëKæ{Uo7ÜSÄı±G'piùÍNŞŞµÊ¤ûw§™Gb*ÔlC%{Òï_Z‡Í÷«"3UÊ"e# æŸ½}j àt"—Í÷\„5bÂsÚ¯ıÓURlÆ— E‚-,¸ö¥óÚı*¿ŸÇNhóıªÔ Ÿxc×špb?Â«‰Iœ& `Š\¤¸²ÊÈ ê(ó½ÇåP‰Á£xô5J$ò²À¹ c—Îj®% ıÚzÌ™íøÕ(¤¶'ŞŞ´ooZa•{O7ÜUX†™&öõ£{zÔ~o¸¥¯sM ³½½iÈæ¢óSÖ”L£¥]&‰Õÿ ¼iŞ`^U¾Ò=©ÂlŠ¨Ä­Éüßö¿J<ßö¿JƒÍ÷o>‚©Ä,X2)***""\r" R"***(ŸüŠ„L@Æ*E¸ v©åDÙıÁ§«œr*!>{R} ÂŸ#%«–’EÇ4½½ª"“ŒĞeQjÔYº.{R‰NzÔ>y=©|ßqUìÙ\¨°²3Š‘ÔÕq'Ò7ÜU*bå'òiÁÇ~*¸‘=iË6ïJµLvĞ±EF’Œpi|ßqUÈÅfH†€ì:óQù¾â”J½Í
fL²€(óÚı*5=hóS¹ªäl9IÃüÔÉ!MVYÕ ”ƒúSQbh¤ç)»×Ö£,1Á›Ï ª±<¨—zúĞGz‹yôÏ‹*&Ñ¿Jr±'“PùNElúSåe(–2CED’ã â$õùì:?xô4	€š‹-Á.})D«M>Q¤Øê]Ì;Ó<Ôõ£ÌSÒ© ådÈëOŞŞµ‘GoÎæûŠ¾[E’nô¢B@¨¼ßqG›î(äcå&±8§ooZ%çµ?Í÷ùr’‡=éâF=W¾N)ÁÂô"K%Ë	'Š_8{Tbã4o¸£•Ù–Ù8¥ó=ªliÁÈãr ä±adxõ—ñã¥WYxíøÓÖ`¹ÊYñ×ô¥ŞŞµ ‘OJ‘%À4ùUÅfME3Í÷qéWÊèÎŞj??Úƒ.î1MEnIæÿ µúR¬Ç<TY¢”?¦*¹
²&óš•df¨Dœr)ÂQ€QËaòÜ—{zÒ‡=ÅEæûŠ<ßqUËÜ\¤»Ï÷iÊÍJ‰g cŠ_<v(‡).öõ§	ÈÚ*?Ú”KôªPNflr”T~<Š~ñèiò²ym°´Ro† 8§ÊÃ•Pwt§Ôblœb—Í÷J!f<:SĞ“œš‡Ì>”ä“U(…™:3“K½}j5|õâ‘¤U«³%Éw¯­(”~•›“Æ)D‡<Š«h.[‡$dõËÇoÆ”HOLQd2q/J]íëQ‘špQBVš àæ”9n…% àæ¾@ş¯r°ÿ z€˜9ÍòqŠu+¤MØQE])ÈO<ÓièAè*Ói@À ’{ÒQGºÈrLz}ÑKMFè¸§T²o¨QE&Ââï>‚ŸQÔ„àdĞMìƒšMã8£Ífm÷¯ùÒòzÓW` ´êsAJ¯JJ*·D6‡«ëKMVQÛ»×ÖÒ!´9[SÁÈÈ¨Á¥(|b‡ª%´L¹+ÖŒÿ ´)«'Ê8¦³Œş5NM†£~´»ÍDFjAŒò)»äIE7Ìö£Ìö¤G0ê2}i¾gµ(`xï@)NJmÂuï@6‰CéFóè*1(=.ñÜRd7aå‰¤¦—…gµ29‰T½i‚˜Fih%È]çĞQ¼ú
J(ØıØş!øS·ŸAQSƒäãZár@äœSª0psNó=¨µ‰rLp$Š]çĞSC}éh!Ş})U‹u¦R«mí@›%ByæQ£Ôï3Ú™7cÃ0)Á$T^gµÆy;›#Ö{bÈ6Œ
x9¤KlzôJvóéLŒR£dç(3l–“#ÔRÈÆ)´¬Œ®É2=h¨ÁÁÍ<8<w¦K“”1^”„Ö›æ{RkB‰Q‰Í81È«A}ı28©ådó’ù¾âšÒdõ¦QŠiårT~iâ` ¨UÀàÓdP–¦m’yşÔß3=
mì‰»dÊùëŠ~óè**w™íRÕŒ›¼ú
7ŸALó=¨ó=ªl˜]Ş}Ï ¦‡é<Ïjj$7¨ıçĞQ¼ú
g™íG™íúÕ[B‰’\–—yôH1ÍP¥ffÇ–Éäş´ªøãµE¸?"œ®•®fÙ&ñèh2(ëQùƒ°£Ìÿ gõ¥dCdÁÆ2õ¥ó}ÅAæ{S©r‘rQ&OQOÏŞıj3Ú•\f•™›y©#|àqPyŸìÒ£Œ_J–®f÷,dzŠPøî?:‡Ìö£Ìö¥Ê"ÊÌGQN{UÒAëš‘d_áœYH“yô¡Îy™şÍ@O"—)“²'GÏZ‘dŒşU]`ÖcåüóC)***""\r" R"***(–VN8Å<0ÇŞÇãUVLu©œt©q2,,¾¿¥?Í÷[$t5%¦d¦LŒd~™=sQƒƒšw™íG.¢wè<1éCúŠÌäRï_Z|Œ‡æJ’(94ğÀÕpÀœNWÇZ=™-X°ŠzÉÇ­@% ¥ó9éQÈC±>óè)D‡<Š‰dãÖ—Ìö£‚a/:Q.;Š„:÷£zúÒäbjå‘8#i|Âzb«qiŞn;~´¹Y.$ûÏ £yôœ´yËO‘‘ÊL²T‹/½U©8©EÆ(äbh±æûŠ<ßqPï_Z7¯­Œ,É„§±ã/ê‘Vœ²+sO,ÉU‹šZ`•AGœµJ ‘2>õ<H 5]dÏ"”Éïš¥ ±9‘=iÂqÒªùÔ¢OÂŸ³@‹bUíO2àgŠ¨$ü*C&H£’Âq&óı©D§±\L¤âœ$Psšj´Xã®iDÙ¨ªx¥ó=©¨E„—ãò§	³éU|Â:Ö²zsT¢ƒ”¶’sK¼ú
®²uç4¾iëUÊƒ”²³1ŠrËš¬³ 9§¬‹Ö—!-4Y`cyşÕœ£GœµJ$ò“ùşÔá =J®$fœ	)***""\r" R"***(RˆœKáGjàœqUù'$ÑUÈK‰gÍ÷	=j~Æœ®3Å5r“o=…&óè)gµgµ_(ôd g’ç¥BdÏ§,Š´ùt‰wŸAN9œ´yËE˜ì‰üÿ jQ)=Wó7t­=fP¸Å¬—ba!h/è*/9})D™ÅZ‹3dÅ˜ô9õ§9àTOÂŸæ{V‰
Ì~óè(Ş}3Ìõ­.õõ§f4˜íçĞR‡$à*3"Š uÔYVD¹¢—põ¨Àğ9[wjÑE)<lFrÔíÿ í~µ r:óKæ{Ur‹”›û_­‰èß­BOZz¸Ç«Ù‰¢@äSƒ3‘QyÔ»×ÖŸ#›&Y1üªDqÜÕ]àtj•[?tÓä‰gÍ÷µWÉõ4dúš¯fO)cÏö£ÎÏ*¾O©§+Á.@ä&ƒß­/˜OLT;×Ö•\ãÒVZ‰ad'§ëR$•^9:ñOzSH®Bo7ÜQæûŠ®ÍÜ2}M>[‡!cÍ÷« #?Ê«‡ÀÆ)Ë2ŒSä)E"}ãĞÑæÓ5œ´¢LŒG ùI~Ğ‚FÏZÌÿ f3Ú´Q)1b:·ë@~~÷ëP‡ÉÆ)êprjìÔ	•ù´ıçĞT*ã9ï3Ú¥ƒ‰2I=©|ßqQ#Œşï3Ú¦ÂåæÓålòH¨ÃƒÖ”z9P¬ÉUıóR,œ{Uulb¤I>^•6b³'#4SO”qKæ{S'•¶L§)***""\r" R"***(=Xš€ŒŠ“$t5I7˜£­Uìj“ÔĞH&¯•‘ù¾â3éPï_ZE9ªH|¤ûÏ ¥YH<Š‡ÎZ œUd¥6}(Ş}*ÙÏàFI£•¢IæûŠ<ÃíQQ’:|—™8`G$Sƒ8ÅB¿v§ËaõàA9¥£4ùDÕÉ|Ïj<×õ¨üÏjRéÚ©D|¶æ¿­F'Ó7)ïKO”,Hç†ıiÛÏ ¨ÁÍ/™íUd
$«)iÂRİAæ{S£“¯ÔC°®[¡4~5JQKç->V‚ÖÒ”?cQùËéJ$*¹n&‰C:Ó–AŒÒ¡½èŞCO“B-bĞ—£Ì'¦*ëÍ9[oj9GÊÏÍª(¢¾ş©æAEP.k…(œ
JU škc6Ç€AN£îŠ``İ)ë´ió¶gµ4œœÒ±ä
@84stIOÂ¤¨Ğ…éNŞ=)***""\r" R"***('«%î:ŠnñèiCBlWÜÒ±ÜhPSJYoÈU'ÜNCG«ËäĞYHéŠh9ÍF2hx89§yÔİÊxiT€yÌ¤Ğåmİ¨çĞ~t×°£Ì†‚Ç{“E ƒĞÑT™aNWƒM§)\`Šz“Î8¨ cµYÓ½Ò–šiÃæ†®fİ‚€psNb¸À¦Ñd$Ğï3Ú3Ú›GÆjlÂèw™íJ­¸ãĞ <‘NÊ„RøûĞÍ´ôíH®«ÔÒ3©äÔŞƒ¼Ïj<Ïjxô4¡Á§fA"œŒâ–š®0: y4á³©«uĞÀ3Ò¤¤F*ZwHN@iÁòqŠA·©»“û¿¥&îG5Ç§Şúˆ0=èÜCH—"B@êi<Ïj'ÿ ®”=1T’!É¶ “ü4d÷ï—¤Èõ§£3™ÛÀïKÏ üéªà
pph²1"}ÑH_¦Ó”©àŠd¹1Àäf¦NŸB1ß4ğàû}i4ŒÛ%'4ÂùÅ7#ÔRäzÔØ‹¡Sï
x89²ƒ’iŞjzÑb¸î´S|Ôõ£ÌSÒ‹3'qÔS|ÁèiÀƒĞÕ%¡›v
rtüi´å`)***""\r" R"***(¨‹¢84QBBnÃÃàc ’3Ö¢Ş=)***""\r" R"***(H%^ ¥ÊÈrh¿Ö‘±Ÿ–›¸g¥¡Ä‡ 4ï3Ú˜\
MãĞÔäIæ{Qæ{S7­&ñèh&ägµ*¶îÕñèiÉ"Œæ7¡&HQMóSÍjzĞe)1|ÍœøR†,2j2CŠ)5s&îJ¥ó=ª5`)CƒSf"Pr3E48Å(p}¾´ÔIrHvI94ààÔy¢—#ÖRor@psO)***""\r" R"***(@$t©ÆsG)Ä”ªÛ{S7CFñèhq„ ƒÒ„œäÔJê½M9X7JJ&oBZr¾>÷çPÓ•€4ùLİ™2·u4å~0ß@$ äfœ³) “O–ærŠ'A§£œqP ğiâLT8Õ‹.:SüÏj¯¼f¤óSÖMHm¢O3Ú•d9À˜´«"ç4¹vJX	¢š$CĞÑ¼z±dˆI8'µ:£IiŞb”šw!Øxsœpnâ£§½(=Á¥Ër¹(sy¥ó;b£Rùˆ¥Ê„Tò2yIA$dŒS•‡CQ,ˆ3Kæ§­>QY“u¢¢Ü=jLQI@Í¡á9âMóSÖ5=iòˆu*±sÅ3ÌZ]ã£–ì-rMëëFõõ¨·/¥Ôt\—‚%Ş¾´© ÇÔhéŞœ1‘úQìÆÒDgµ=\cPo†ãĞÑÈÉ,	0sŠzÉ‘ëïUÖEŒÔ‹*íëUÈ4‘/™íK½}j/5=iwŠ¥ q'ó=©Õº·J~ñèir4!İ)CœóLŞ=)***""\r" R"***(Ç¡¢ÌZ2Tq‘ëéOó=ª êhÈõùYùÔäqÚ«dzŠz>y-O•Ø9QgÌ `O3Ú£YsG˜´Ô+‰Hâ$ÈÎ*¿š´¢A3UÈ&‹
r3J	*cšPàĞ¢É±a_ªU|©ª¡×¤¸<Õ(‰Ä•¤Éõ¤ó=©HñŒ~”İëV‘Ÿ(ğù8Å=IÈâ¡YjE•3ŸJ´ƒ”–—sõœôyÉïO”9Pú)‚d>´¢E4ùDÒJªO Ó¨:Ò¬ñŒ÷¦‘$ªHêy¥sÍDncá*®@h8î*A'Š¯æ§­(#i¤Ék±?™íGš?»P«&pM8¸#­A‚‰ ~zRäzŠ¯¸zÑ‘ê+E å,dzŠMãÒ¢YzRù©ëT©Ü9Q'™íOY3ïPy©ëJ$R2)***""\r" R"***(W&ƒkBq æ3Ú£‡¿…)u¦£blÇùÔ¢SŞ£.´«"c~•|¨[%dÖ—Ìö¨Ä‹(Ş=)***""\r" R"***(
7+&GNõ*9Z¬¬@ÈïR¤€pZŸ ù	É'­py&›¼zvaËb^}çG>ƒó¨Ã‚ir=ir‡)"±$SÕ²qŠ…HšrÊ ò)***""\r" R"***()DI=iáÈëÍ@²©è)***""\r" R"***(8K‘Ö[•Ê‰¼ÏjC(¡ÈõdzŠj:‚V%3ñIç5G‘ê(Èõ\¥$LˆÎiDœt¨2¾¢¤`r(å‘($t§ÉÆ*?53ŒÔ›ãôª³˜àpsNó=©ÔÒäzÒ°Ò]GÉÆ)áÈ¨Ôàæœ†„×b@Aèij<ƒĞÓ“ iò»”’>ôêb0óNŞ=)***""\r" R"***(+4ÇÊ($ŠzŒÔ{Ç¡§,¨3CW'”™I#&b¢YShæ—ÌZi*,	8v§GJ®²zSÖOC­ZV‰)$òM&õõ¨ÚOza$õ«³+&ó=¨ó=ªrÁÏ4ìÇÊÉ<ÏjUmÇ¦R© äÒhH÷æ¤Ysß5`iñ•ÆsT•ÅfIæ{Qæ{Sr=E¢ªÁfHFiÁğ1Š„c9íN `f˜(’yÔyÔÍãĞĞõJ#å%§yÔÀàõãëA#f´Q`Ğğã<Š]ëëPRƒƒ“O–áÊN®7qNó=ª à÷¥Èõùl¤áèiÊÛ{Uuu'ô©Õzšb³¹/™íG™íQù©Œæ1OJ®F>RO3Ú”JG*=ãĞÒƒ‘š¾På&Yıhó¥F® Å.ñèhå‚&ØëRG ïU•ˆêD‘z9Fá¡ùÀXô™>¦Š+óÓúe´>¦”9ızJ)¦O3qõ¡[&’”NUÑ.c•³ÒûÔÀ»zRœv¥s7!ÛÇ¡£xô4ÂÀI¼z1/˜LÒ†$g&¢	 ¾_ÈÕ-»’y¸8æ•e÷üê/0{Ñœö4îÉ,	7wüéş`ô5å`Fqõ¥ÜÇ×ó¥s&Ù1p}hŞ=)***""\r" R"***(Dç’iDŠO‚%	â—'ÔÔjÀ7Zvñèj“3m\vO©¥WÇ\šfñèiCéTCz’«ñòš2}MG’:2}M4‘™&O©¥Gz‹wû_­(‘@äÕ(“ş¢L÷5‘MÇ¡ bÀqŠz¶5X1ÆA©2Ş´&HÒó×ò¤ó}Í2Šù¬<I“ŒšpnrI¨ÁÁÉ¥Ş=)***""\r" R"***(&®'"MãĞÑ¼zxô4o†TMÙ&ñèhŞ=)***""\r" R"***(G¼zPÁºSµ†˜ıãĞÒ‚È¦R«ªŒ@î‡‚GJ~ü(çğ˜§¥bÔØ—-	D™îxqŠ¯¼z_7ÜÓJÆm“ï†—Í÷5c¿­;ÌSÒ‡¡)Ü—Í÷4y¾æ¢Ş¾†ãŞ¥j™dãüiC°9ÍDŒ2)***""\r" R"***(;xô5VD9hJ²18&œ‡CP	lÒù¾æ©#'-K!9$Ñæz‰dÈçô£xô4ÔDäÉD€)áÁ¨‚qOV)Ù
ö'Üq€*Ş£(&—ÍOZv%È”Iõ§" óSÖ8xşu<¢æ&2óåK¸ã˜=éVQI£”†É2}M(b$Ó<Ôõ Ê¾´’ “xô4ånâ¡óSÖ*ö5\¤·tM“êiË!JƒÍ÷4äqÔš\¦RdŞoÖ7ÜÔ[Ç¡£ÌZ|¨ÍêKæûš<ßsQ‡SA`;Ó%»y¾æ•e÷üêãĞÑ¼z	l³æûšœ¿Şıj “?ÄN,OzM\Í²ÃH¤pi7ÿ µúÕ|ŸSJƒ’M.TKdûÿ Úıi<ßsQy‹G˜¾ôùlD™(›¿/ŸíPïôyŠiräOænb•Xj$`:ş”»Ç¡¥f+–À£xô5 tŠz¸Ç5<¤2O1}èŞ=)***""\r" R"***(F$^”o†…7¹)—ëJ²ÿ “Pï†O”–‰^zşT,¾ıê:4X‚7ÜÓ’^Îj)***""\r" R"***(ãĞÓ‘ÔrM>PlŸÍ÷4y¾æ¡iëI¸úÒ±™?›îjd—¯&©«ã®jE”­úÑËrYkÍ÷4y¾æ«‰AèOçJr:9lCv'ósÆM*¹ëš…XmëR©G4X–Û$I1R,™ïPSƒ`HzNÉõ5š´¾o¹£–æM\˜9ï7ÜÕ7ÜÑæûš\„Ø°& äNäòj°—#£¿ëG)-"Ø˜„Ò‰Êô&ª,´á6=hp¹)***""\r" R"***(ÒbÜ“N‘Ğš¨“ƒŞ—ÎŞ?%r—|MrƒÆªy¹îiË"ã“G#'”·æîGçFÿ ö¿Z®Ñ¿ZpqĞæ…Z,	cšzÜy8¨ªzRïùH,³ëG›îjøêß­'›ÏSG!<¥¥—ÔÒùÃ±?TãœšrË’)***""\r" R"***(…(²×›îiwÿ µúÕo7ÜÓ–e#š,6‰¼ß­(œ™¨DŠiÙ¡ªåĞD¿h4¢RG'ò¨hÏáJÂ²'ãÖ²ü£¯áUÃëKæ}i¨‘`MZx™q÷ª ›¿ãO)ïO‘¡–’b:Î¤ûA÷ªÛ×Öƒ.OÂ…L‹?h>ô} ûÕo7ÜĞ$ÉêjÔI,ı ûÒ¬ù<š®®3Ë~´»Ç¡ªä@YÑ¿ZzËïùUO0™§¬£<ŸÊ§w¹lNqÇ†bÇ’j-ëØÑ½}iX,N®1ÉÍ(”™ªşj7QçïÎ©Dmf7åJ'ëUD‹M/š´ùD\}êTœºxªbOsR, ?Z9Dµö†'4¾kúÕ0{Òù¾æ­@\¤âf&œ'ëÖ«y¾æ”IÆwVŠqL±öƒïJ''½Uó÷gûF­CPöe±7«~´å›Œ†ª‰"÷oÎæ(İUÈ.BÏŸíHfõ?J¬fç†ıi<ÓœäSTî.RßNYxêj¢ÊsÉ§¬¼uüª½ˆå-yÔõŸÇj¦$ç©üiÂb7~´{1ò–üîy‚sÖ«,¤u4y¾æ´P%Ëo¹¥ßş×ëU¼ßs@“?ÄjÔÙ–Uùûß­;xô5]÷©Û÷¿Z|¡ËbmãĞÒ‰BôO©¥Wï55²,,Ä)|×õªâQØš_7ÜÕ(E“ù¯ëGšşµrFA4åaĞš¥Y“¬¯´sNY}OçP{2}MW ùKk&G_ÖŸæ§­TqŒšx‘z(–|ßsG›îj¹—'¿á@—¦Ÿ"+°%ÁïJ&$ğ*¾O©§+zş4r)***""\r" R"***(A"Çšş´y¯ëPïÿ kõ£q=õ£‘•Ê‰ÄÌ:“øSÖSİ‰ª¹>µ&à:7ëUìÂÈŸÍ÷4y¾æ ßş×ëJ²(š,5É„™îiwï~µåõ§«€1K”\¨vO©§«ñß­E¼zPÀÑÊ
(°o­?x÷ªâD=éL¹=ÿ 
j)E™îiD„toÖ«	qÜÓ„ÀhpYy4¾o¹ªâE'ƒK¿ı¯Ö§TYYiŞo¹ªªä†§+±ïO“@å-¤Ùõ¥ó}ÍCiÛÇ¡©å+&YTiÁÔôªÛÇ½9\Ö§”\­VE§	G@MW.´	 éš¥rÕÆ¥(—ÜÕa+c­9$'€:µä,oÿ kõ£û_­E¼Q¼z®R¹Q.ÿ ö¿Zr1È q¸§,˜=hqRÆO©£'ÔÔ"L÷4»ÿ Úıjl¤¹>¦•\¯Rjÿ í~´ªã¹Ík‹—Ro7ÜÒ‡Ïñ~µñèi<Å÷ªåCä,,˜M;ÎÅWY{N;Šj"ödû‰ç4õ&¡vÉ u=êìƒ–Äo¹§n>µ`jMëëL\£²}M>¦›½}hŞ=)***""\r" R"***((Éõ4dúšäïMó}Í4®$ÁØt4¢VïŸÂ¡p	§!'95iXRuw9§	;dÔQ÷§UY”™\c“šQ'`MB;ŸÂœ¥}h°r«¾´¡Á¨ÁP0)***""\r" R"***(.G¨¡$ÇÊLb—x¨2}iÛ×ÒŸ*‰ùÑ½}i¥‰ïJvtÌò+ótÓ?£…Éõ4ªIa“IŸóŠTûÔî‰rFHèh¤Ü£½9BNriÄàdÔaı)***""\r" R"***(÷&•®ÉæB¹ñIŒÑŸóŠ)İ"n&=)***""\r" R"***((Ïz3Ú”lÇ=i¦Æ› „õ§ e Ğ@Æh»&Rb”dúš@AèijÉlU$·Zváœgše*Mrd‰÷…>˜„iÛ×Ö©l`Û¸´d†“zúĞ=)***""\r" R"***(Q"äúš2}MPKm&Š(ªLWcÓîŠZj°Òï_Z«’É(iCç£‹zúÓ£eõ –M½}i†84Æ`^qLó±ı)¥s;dúšPÄµöõ£{zÓåb$Ü}i2}M0ÈGSIæÿ µúU™+c©§èjïz:š–…Ì?'ÔÑ’i7¯­×Ö¢Â»:r°Ç&˜IÀ4¤ÔÓ%¶‡ï_Z7¯­G½}izĞ.fI“êhÉõ4Õ,ßÅNé@›M;zúÔe—¹£zúÕ(¢¹ qœÍ.O©¨ĞŒƒ)û×Ö“VdV-Á§p)ˆ@9Ïjvõõ¦˜šC‘€ÎM;zúÔ{—9Í×Ö´IÖ¤›×Ö”7‹zúÒ‰;¦¢ˆdÊã1æ—zúÔ&B:šO7ı¯Ò¯•X–É÷/­—Ö¡ŞÇ½<İ)***""\r" R"***(&š&ì“'ÔÑ“êiÔÑ½}iYİ…Éõ4¡á“MŞ¾´o_Z®TKd›×Ö•[Š‹zúĞ$¡©±D¹oïrÈsŒâ£Wõ4 ƒÈ4X†É<ÁıãFğOZzúÒ‚J,A(b;Ğ\šb°É¥Ş¾´X‰$.O©£'ÔÒo_Z7¯­2%VâŸ½}j¸e=)***""\r" R"***(I½}ir“!ìÃnãêi¨SCäç<Qkİ‰’Ã&”¾:SAdRnQŞ‹]™9;Ü}iU¿¼i›×Öœ…SE®<3FO©¤]¿ÃKE›C•†94åcÔ”1gœH»$.M&O©¤ å³Fõõ¡DOR@ãšPùèÆ¢Ş¾´)***""\r" R"***(ĞÓå!Ü—'ÔÑ“êi7¯­×Ö¥¦„.O©¥W9ÁéëMŞ¾´o_Zi]&õõ¥¸5õõ H ÓåBz’äúšz±nµ¿÷88†ªQFoB@Hèië'œToû_¥_Ò‡È,	9ûÔô—æüª¸u#9 H À4r	» €wQæïª²äõÍ;põ¥ÈAedô9§ùƒûÆ«#v-ùÓ÷·­.RZlœI3FO©¨7·­ÛÖR\.N\¯%'˜?¼j%_Î—zúÑÊK‰2»A§	vªàƒĞÓÔĞ¢KEàòiw¯­@ ıiD„ô4ù.K‰7˜ñQæï‰_˜ş”¡ÔƒM@–L³6Š‘g'5¸ÛËRî_Z|„´XWcÑªE¦ª‡#ƒR£†‘C›EëëFõõ¨÷¯­×Ö§’MëëFõõ¨÷¯­èhä’yƒûÆ”>z1¨éT€y¡$;²U÷8©N:ãéPo_ZUîš|‚'ó÷`şñ¨w·­ÛÖŸ#o0xÒ†$d1¨CŒrh/éùĞ 4®N«N c5\8Ç&ëëV >RĞr8Îi|×õªË/=sOóÚı*¹DŞkúÒ«¹ïÇÖ óÚı)Ra´r ²,«NÉõ5J3ÉçÖŸæÿ µúQÊ¤™>¦Ç½B²yjp‘…©r IÏ4ííëP$£iŞoû_¥ˆvD„ã’i7¯­F]IÉ4 ‚2)***""\r" R"***(ZŠ°	@Í(—<TTw4ù °’pjE“ĞçëUƒ/LÔ›—ÖŸ Y–<ÁıãKæïUs/<<ßö¿J¥W)cÍÿ kô ËŸâ¨„Œ† ¹;¿Jµ qH›ÌŞ4¡ÉèMWó©ü©Ë+ÿ UZ$ù>¦”0–Í@&'©Å;{õjZ“o_Z7¯­Aæÿ µúP%ÉÆêj"i²0zœ²±Š®ç“OV `®Ar²o5ıiÁ›®j)***""\r" R"***(íë@r:óG r–|×õ§Áåª äuæ‚ç<SPAÊÉ¼Îsºœ²Á5\3g“NŞ¾µih¬°v4yƒûÆ GëOŞ¾´ÔPryƒûÆ•dô9¨¡§©Uş*|¨\¤¨Äû})Û­F†íëUÊW*&Y8äâ”IÏŞ¨·­80<w¢ÌN%…“N=©|Áıê…X‚iw¯­
-‹”—Ìÿ j”;­B$¡¥Ñªãò“ùƒûÆœ²ŒãuWŞŞ´lòkNPåe¯0xÑæï®IÆiÉ÷…>[MyƒûÆ²wÏj†€HéI¦ÅfOæïq‘·÷=}i¨üŸSNV ri›×ÖëëUÊŠ$:©O”eª¸`x¬ `š[²¹S%ó÷`şñ¨÷¯­/Z\¡Ê‰·âæïT[—ÖËëO•”‘*Ê:gó§ï_Z¯½}iU”M¬	÷¯­(|ôj‰JãKC‰åDèàôjz¶:šª	)***""\r" R"***(H	)***""\r" R"***(Kˆr¢Ò>Ş§'£M<HF©äRP[=iã8æ¡GrÔá(ê\AÄ™X¥Ş¾µu#9£zúÑÊ„‘(c)***""\r" R"***((fê0ç±§_Z¤¬¬›'ÔÑ“êj/7œn¥ŞŞµvRLŸSJŒrE½½iÈNfPå&Éõ4›©¦ooZUsŸ˜ÑÊ£ò}M8HF¦S€@2M\UùPá'?zœµîéC èiÙ‡)&õõ§=sùÔC½=F3Eƒ”0=ê@ÊZ‚§Š,É±-)f'­0Š‘ëTX\ŸSFO©¤ÈõdzŠ ’qš67¥Fsš~G¨ ,5TƒÈ©œšh ô4SJâåD€‘ĞÒäúšj :ÒÕ%ar°yäÒ† õ¤ N3úS)"EbGZPÄõé”f—zúÕrŠÈ”1ÀæŸ¹}j7ÅúR†bzÕ(Ççv1E3yôëŠü·˜ıı´‡Ğ0qLy"‘ê(R2ÌZ“™¢ŒQUrn>>üÒğ=1[1JI'&‹İ÷‘ê(ÈõÂ@êi2=E4®"L¯¨£åŒS2=h'T•„İ‡yÔyÔÌQKT™7c¼ÏoÖ—Î'ƒL¢¬fH¤dsŞŸ‘ê*$´ìQA$…€èß­*¶:0ÍE¸zÒ†ÁÈ4"ecM88T*ù<ÒäzŠ¤ô3dŞaÍ'˜¼*2Iîh¤Û$—Ì?Ş ;w¨©êr)¦ÄÉ¸äÑ‘ê)”V‰?#ÔR‚GJ¤È=)***""\r" R"***(P›°üQFG¨¦SI‘ê*¬A&G¨¡›ƒQäzŠ^µB{
X¦’Š(3l#¡©ÉéQÓ¨ÿ ëÒaÌ‡ïoZ7·­7#ÔQ‘ê*Ì;{“Ïµ9N@8¨ò=EH¤mäÕ5 7t-=HÀät¨ò=E¢¤’PGcJ\ãš‹8ïJ\‘Šh†;#ÔQ‘ê)„ÔÒdzŠ±†çƒÍ9Xç“P‚AÈ¥Ş};1]Áá‡Jvòz5@­“Í9[1O”–Éw·­ÛÖ˜­¸§d†šØ†ÅŞŞ´åÉ^M2•Xô¢±)***""\r" R"***(¤>Š{Ó‚©İL†Å^ƒéNŠh dRäzÒd&É	 S ~™'­ì‰r»gŠ7·­%X†ÅŞŞ´ªÇ<šnG­ÔĞCš$†œ÷¨C…èE9[=qAœ¤<¹=8§+drj<QFG¨¢×#™’dzŠpc)***""\r" R"***(E‘ëKæ  ­RD¶I½½iÊWEA¿ı¯Ö—y£”ÉÈŸpõ£Ì?Ş¡¢“V%¶H_<àÔtƒ‘HDÊıçC6£)***""\r" R"***(I¹¢…%¸õbNRä~£Èõ¤ÔÓåh‡rEsØÓ•²95½(ó}Å.K‰²pÄ)***""\r" R"***(.öõªâR:0§$rß­_%‘)***""\r" R"***(êKæïRn¢˜Hîi2=EO+$–¤†¢ÎE(>‡ò§ÊEÙ)r:µ'˜¼*6l“ùÓ„uÅ.R–¨±ægø…'˜¼*3éJ²dã"Ÿ)6dŞaşğ¥ŞOCPäzŠPà‚(åìXµùÓŒœtıj·˜OLSƒ–îj”t%´Ñ7˜½NVã“Pn´¢Lw‰ªåd2l_Ö”I7
ƒÌ=±NäŠ9Y,˜Hs×?CO`u\0ìiàŒir’ÕÉ–O|Ôqş÷ëU.óè*TA«“ù‡ûÂœ²g¯çU·ŸANY1Ö©GBlË ÷—{zÔ+%;Í÷."$ŞŞ´ªÙêj/7ÜQæûŠ@œ>:5g?z«™3ü_­LüêÔ	h¸²äu£Ì?ŞPJGF¢F'Õ¨´[z 9š…[ e¹§yâBK)1éë!èNj¢ËïùT‹/¿åIÀÌ¶%=Ê@Èj¯¿ı¯Ö‚Ş­úÔò!7bq14ôúş5T8õ§, ñŸÊR^aşğ§+ƒÆj®ÿ ö¿ZU)ûß­©l>:0£Ì?ŞYdÏñ~´åb:SQÔ	üÃıáG˜¼*7ÜQæûŠ®P'óv	÷…@$ÉíNz\¥&‰„‡=sOq÷ª¾áıïÖ—Í÷j#æE);…/Ú¨üêº6î¤SªùPÉ¾Ñî?:_9ªç"‘ê)rBU³õ§‰yÇãP ğE/›î(ä“,«óÎ)â\u#óª©/½=\¤Rä‘m.;Rı úÎ«¡óúÒäzŠ®DM‘`\Ú=j€H À"—Ì=±MBÀ’DâRFKRï'£T!‘K¸{õ§Ê2ua†§#­WØ§†ç†ıj¹.;6Yó÷©<ÃıáQdzŠ2=E%¬›Ì?Ş¥Y<µBE/›î*ÔF¢M‘ê)±¦¢ó}Åo¸«QÔvDË)¯J8=xª¾o¸§¬¿äÖŠ$8“äzŠ2=ECæÓo>‚«Rpü`0§©y5[Ìj<×õ¡E”‘g#ÔSƒpj°Ÿ”¢c¢©@c{zÓ÷Zª%#©§oÿ kõ£‘‚M“äzş´¡€9U}ÿ í~´Ç;¿Z¥>RÊ¾[ï
xp:0ªªär>´á&?‹õ¦ ÅÈYGòÃ¥=\/qùÕT“'’*Dlç-úÓPbåE)He,x5á‡-úÓ—jŒnıj”A+ŞŞ´á3ÕG­_QO‘"¬™:Ìvğ)D¬{Ô!Èb”9>”(jªÄŞaşğ¥ æ¡Èõ ú×”N$»ÛÖœ„‘œ÷¦P	)***""\r" R"***(¤ò“+òiÊàæ Ş}(sÁ8ü*’Çš½ÿ j÷şu_yì)7ŸAO”¾DZW)***""\r" R"***(ÿ ë§ÆÀ½U³Ó4øË`óG(œ9¢”H À"«äúšr94r‡!8ç¨úR—=…C‘ØÓÔŒri5a¨’+pêp}‡#ÔRî£~´%rì‹ ú~G¨ªÊíÓùS²}M£å'Èõ»€èÂ Ü}iCƒÁªP@ÓDêÄ°$ŒSò;UpH<w˜Ôr‹–äèFy=©áñÑ…VY˜uæ”K“SÊ.FZYHàÒùÍQFG­.G¨©åe”Ôõ|Œ
¯¸zÓÕ†95#HœLÀcñ!#­B¤c“K¸{õ¥ÊW):°À9§#¯5_y§#±äšC•–wZ_0ÿ z«ï>‚•_ERD¸ïoZUs;úÔ^aö¥ÇÚ®×'”Ÿ{zÑ½½j+v4y¯ëO”®BÂÊÂŸ½½j²ÈOOÖ¥@ëRã`P&VÈäÒäzŠ‡yôo>‚©D|¤Êø8È>Õ"ÉÇ«É5"‘M>Qò“y‡ûÂ”IŸÿ ]Cz2GCG(r¢À>†”¹îjf9æ—9ªH—ù´ ‘È5($t§f+"UçúÓüÃıê€8î)UÉ4(‹”['“NB*ŸSJ¼õcùÖŠ!ÊÉÖO|ÒùÕdzÓ²=E>T£Ä¤tyÍéLÈ=)***""\r" R"***(ÔPÔQ"»šPÄv¨Ã1K¼ú
¤‡ÈLFiÈÄıãP+¹èiê	äçó§Ê%ÏSĞÔy'©©}*:üGîr
(¢’l¢Š*Áè:>ô¬Á{S(¦¯rI94š)
“ü\U“Í £”S|¿z<¿z¤ÄäÇR‡ b™åûÓ€ÀÅRb½Å.HÅ&O©¥
OAJS9ªæ%»¥²2Ôú€psChÍÈ“)ÛÒ1?ÃÇ®ha¸c4&ƒ˜vóè)ÊÅºÔj»NsO@Fr*¯r$Œ“œšˆ8ĞHŠoQêr2iÊøÅB:Ÿ­HŸtU&Clvóè(Ü}iÉ÷E-Zv2m‘äúšp“¥:Š°æ§$ÑEîÉl)Ci(¡7pº­¸ãµVd²Jk1›E1¼ú
7ŸAIEóS‘š\ŸZ`LŒæœ*¬˜9B:xéÍF	*AĞRjÄs²CÀÍ0¾xñ¤¢¥+Ød¦•>ğ¤ Õ'Ğ›¢J)¡òqŠuR0R†+Ò’ŠbçCÔæ?bŒ?ZĞ—$IEG@8š¹)***""\r" R"***(’‡ b”?¨¦(!FE(ô¦Khr3FHèhÒ3»Ï  ÉœRR?İ5VFrÍ‘Òš˜àÓiPƒ=iÚÄ±üúĞI={R1Ú3ŠO3Ú•‘›êUrÏ>”Õmİ©i[R¸»Ï ¥ßÇNi´SJÆm±Şcu¤ŞÔ”U%r[± 9§¯Aô¨#¥H:
±¹&HèiwŸAQQCVv%i)¢F-ŒñL¥O¼)-Énäˆ9ÍÏ ¦?OÆ›Z¨ˆ™X“ƒN¨Pœã=©êÛ{Rh‡¸òIÉ¢›æ{R1ÜsŠ-búPäTTôû¢´!»ŞŞÔ¡È9şTÑÍ¹LÜ‰D‡”IJ†¤£\ÄœÕÌzš	'­ùs $Ó•É8¦ÑO”®IEGE>FI(b½)L˜nj%m½©Êwâš„ö¼ú
7ŸAIEW)„‡4õãüj*(ål	wŸANæ  : ´$­Iæ{Uelu§ÔòÛD­')¹=ê:(åÛ'W'Œš\ŸSP©ä)***""\r" R"***(ß†)Ô¹)***""\r" R"***(2Båz“H®Íi”UÆW%G|ıiÊI5b:7·­W(6‰éwµ@²yüéâL™¦¢ÌäXW;zQ¼ú
„ŒÒÓöw3³&ç?•H²cÿ ­P/Aô¥”¹…ŒŸSK¸úÔTdô—³d¶‰wŸAJ$ óPÑB›,,„?Z]çĞU`Hèièí´ùgîœS„*¾öõ¥Wàäı(äLŸyôo>‚ ó=¨3È£|¬°$9 Èİ‰¨Aî)***""\r" R"***(=y š9'rPÌFwR†=ÿ EO^ƒéT‘J(LŸæ¿­CNó=©òDHÄàÓÃzÔgµgµRÊJÄşaô£yô`N3Ï¥->F&™:IÏµ?ÌaÒ«"œ	î(åèèYI‰û¦æ¿­B¯œ…?Z)¨•‰OriDøõªôƒš|ƒIÄüt¥óıª°9¥¦ ¥”õï<zUPãÔªÛ»UòÌŸÍZŒN3QùÔyÔr°³&Éõ4¡ˆ=j3Ú”1?ÃÇ®hQl,É·ŸAN(r*¹\¤ôèÉ9É¨¥89yªQhN,°Mij/3¶?ZpÉŒU¨ŠÍó_Öœ¬Äg5j •ÉwZ7ŸAQQT¢>RÇ™şÕ.ãëQQMC°r’î>´o>‚£E/™íO‘‰Ä•$9¼ú
‰àŞ”õmÇ£‘…™"¹&®GRjt}é¨)***""\r" R"***(G¹:KÇSNó}ÍEzuÊ‰Ø£Ïö¨è«QAÊ‰>ĞiÂW#9¨iÁğ1Š¥)***""\r" R"***(v%æ¤G<â ©#¥W)+VMæ¿­9]ˆÎj:PÄt4¹h~O©¥AÎj"rriSï
¥$Kæ{Qæ{Shªå)E2DqÎ*DqØT(IÎM=Wwz\¢åH—Ìö§È¨|¿zPœÑf¨–¿v E=rTK–âå% p1QÓ•Æ0hä)E“d†¤¨cïN ´œ]‚ÖÇ4İçĞRQB@9]³OŞŞµqÇ­>­$ÇËqw·­H÷¨Ó¯áOÎ9©v*&½:¢Vµ-O(¹Y%*¾1QR‡Ú1Š9n4‰Ö`
Ò‰èµ9Å9wgå¥ÈW-É„¤u§‰qÔãéP©`:ıj@¤ô£|¬—yôä­2€psK•˜È{
MçĞS<ÏjäãJ6'”~óè(Ş}%*uü)Ù(å-ßŠ‘½i”èûÒ¶£²“êi2Ş´QNÈ,‡ sšz8ÇJŠ•cã­4†’'¸4¡Û;szÑÈ«!ıj„?ZhRz
’…ÊĞĞäœSÇ"Š*ÒQÊX´êŠ,ƒ•'_ÂP"œ­»µRˆr“+míK¼ç¥CERHvE”~8»Ï ªÁğ1Šx9ªQ‰·ŸAFóè)‰÷E-Ur’q‘NYÿ ëSW úQT8ŸŸ‹M! šŒ’NI¢¿Ó¡û?3d…CØSi8¡!9ŞŞ´cÁ5Í'>ƒóª!Ì™[ojr¶êŠ<óšz¶ŞÔä>˜ÿ z—Ìö¦<ƒ'×Ò‚.…E.öõ¦©ÈÎ)àã¢W%ÊÃ÷¿j7·­3Ìö§FjÒbç%# £ÌÉéúÓO Ó7·­RW5ÉÉ dÓLƒ°¨ƒ·zPù8ÅfnD¢b;Qç53 õ˜‚©\\Ä¢R{ş”ä,İMCNBNrj¬ÄäN×ğ£pşà¨©U¶Œb„µ!É’‡çŠ_3ŠŒÜş”`z
´‰r$óš—{‘‘Q`z
PHéUÊO18Î&Ÿæ{Upø(ó;ãõ¡\‡"bIëA8¨|ÏoÖ3Ú¨›²O3Ú3Ûõ¨Ãäãâ@ëTš0ï3Ú•[qÆ*/3Ú‚ç°ªš%$¦ƒ6Ê ,OSN@Fr(!É²_9©VFašŸtPKmâœFqQÒ àŠjı	»d ‘ÒœÔU}ãĞÑæ{S³aï<Îøıi|ÁïPdúÔ„àf…¸íàœN¨|Ïj˜œM+äº†#éNVÜqŠ…~ğ§Ó2rw%GZ_3Ûõ¨h«ĞWdşq#‘BÃ8¨U¶ö¥ó=©Šö,'OÆU„Ì:R¬ŒFhµÅ{–)C0ïU÷·­ÛÖ«”9‘?›şÕ=ö¨È§yÔÒ²2rìN\”˜'©¨|Ïj<Ïjfm²\AK¿hëPùÔoÅ4®I!“”ŒÀô¨Ù·b’¬›¦J¥60j%m½©^ŞÔ¬„ìMæ{~´yÕ_Ìö£Ìöª³!¦Xó=©|ãµ±#8Å89Ç"•µ!¢_9¨Ôâ ''4‹&=ª¹Iµ‹‰'¦b ¬²â†“'Ö’L‡¹cÏoJ<æªÂNz~´¼úÎªÈ–Ñ`JÌqëG>ƒó¨ˆ=;Ìö¦‘-“«y¾gµWó=¨ó=¨³$±æ1Š<Ìu­@­»µ($T‰¼ÑéJ&5*¾ÑŒ~´ìŒÚ¹adÈÏZ_3Ú S‘œRÁÆ*”Lİ‘cÌç¥8JsÃUpr3K½½iò‹Bc1Ï«)=MGE¨’o3Ú‘¤ÀÏJŠŠ@“Íÿ kô LäÔtU¨¢\‰|å¥YÏE¨h§Ê…{“ùÍGœÕùP‰ÄÇ<Ó–LŒõ÷ªÀr)êIPI¥ÊUô'Zp=Áªşô»›ÖRt,ù˜íúÓ¼ßö¿J©½½i|Ïj9ÏœÔyÍUÌŸZO4ûşuJš"Ì´³y§}§Şª¤½;xô4rXE´ûÒ‰ÉéU·CJ%ÇAB€R&9j¬³0hó=ªÔ4M–<ÏjQ31U¼Ïj<Ïj¯fCEÅˆÍ(˜¦©‰ˆíGœÔ(ÊËßhaÑ³NYòr)***""\r" R"***(g‰›9ÍJ³zÓtÉ’eÿ 9¨óš©ùÍGœÔ{3;<æ£Ï~ÕLLÔ¢^qœÑìÃ”¶'qÜştå½sUâœ¯ÙM.Aò–üæô¥3Öª=éË/¾){6e­íÜÒ«Œ|Æªù¿í~”¢aÜÑìÙJ%¿7ıªp¸ã“TÄ€ö§«£4ıšCå-,äóšLØªBNz~´ñ';SäVZ°4ííëUDÇ¹§ùÕ\£³'ŞŞ´¾gµWó=¨ó=¨å2ÊÈÉï9j |1N«P[––PxÍ8L;š¨§ààõâMC‘eÅ;ÎZ¤;sNó=©ò”¸. éGÚj ˜€´å˜ƒÖfƒ”´''‘NÄg5TL@ÆÚrÌ½ÉªQAªØ¶¬@ëR$ pjšÎq×ôsÚ«jå³.OJ€‘PÑO‘”NJQpIÀ¨h§È†•Éüæ§,¹=sU¨†T_%‹^aëNYÈêj¨ZPàæš‚şÑî:rÎÌ3¿õª;Ç¡§,œuÅW"ïêsøÑæoÎ©‡$d5<1a’i¨“ÊYó–”IÜÖ«‡øhó=«HÓRÈ§yëU©Şgµ_"Rq2çN±8«ÉÆ)À‘ĞÑËa¨„ŒZ_9ª²;nëOŞŞ´¹C‘“yÍOILÕ`ç½9eÛÑi¨‹”¶“psKç5UY²8æ—Í?äÓPWRØ”w4y£Ûóª¡·sKV "ÏœéÊàò)***""\r" R"***(UHÍ<dw¦¢‡Ê‹K ã­H²ƒĞU5`zÿ :•eÇ|U(‹”µç-rÕñèiCEƒ•“ùÔå“ ÏáUéPœ)YEŸ3BzÖ¡¢‹)***""\r" R"***(‰™xÎŸíŒbªÒ‰CÍ
,v¹kÏ?İ«#AÅU`ô©@G<Óå°r–<ÃĞóøÒ‰Ütşu[xÎ1OWÀÀ­·™0˜¦¤IxëU¼ÏjxsIÆÃ³-,¸ïŠ“Ïnã5W{{Sòzæ—(r“ùçû¢9½*ŸSFO©£•)aeÉäşıâ«+âœI=M¨v,	3À§¬ ñª¡ÈëNVİÚUr¬[YA*<Ïj®®@94o†Ÿ*bI²Ï›´`<æªûÁšPA—)Ve‘sÇ4õ•›¥VP6Šz°Şôr+•ˆzËøª¡òøÔŠ@Ö¥À¢Ïš[’)CƒUùô(,::9|ˆ³,P	ƒU÷¿µ.öõı(å™`9ïNIAUw·­9eÇ¦¡på-#­H’Œ|ÕMdÏz‘væ©BÁk )***""\r" R"***('˜¼*;qH	"«‘ÊZIqÍ=eb2*ª€sR)%rhå‘6öõ§+^j‘ĞÒ†+ÒŸ)Z–m½)æOj¨®=qRy¾æ§–äò²3Ú—xô5\8n¦–©E”ŸÎ#€(sŠ…~ğ§ÓåCå± •˜âœ$aPÒ«míLvDÊÄñÚ–¢VİÚ–™J$™ ärÈAçó¨A#‘NV'ƒG+‰8‘iD˜ëPäãü)ÛøÁJ7ŠE…“ÛÖ”NsÍVó=©U³íŠµ'çût4ÌŸSAcƒÍ0»WâéŸ­ó+j<¹$ši‘ÇëM;ˆÁj*ˆrœç4åÎyÏJE iı)İØsØÒ™â’˜ıiÚhw›îi€úÓsíG&«”‹¤8I9ëÚ—ÌôÌbŠ­ˆrq#õ§y¾æ£Ş=)***""\r" R"***(&ñèjÖÄódúš*=ÍïùÔ•H— ¢Š*®O:9 ç4Ö8çİÇÖ©!7}‰<Æô¥ót¨ÃúÒ†)***""\r" R"***(Ò¬†ä<J{çğ¥óÔÓ)Ö6N²ñ×ò¥óqÏ5¶GÑ“êiÙ‘Ì‰üìóÍo¹¨ÓîŠZir@ÄŒäÓ·CPäúš’´Q%Èqq)7ŸAIE;!]W$Ó²OSLO¼)ôŒM°¢Š*ˆæaNıêm	±ÛÇ¡§+ddQÒ«ĞO0üŸSMg9éHX“Áâ’©!);;Šp9¨èÉ)***""\r" R"***(PÔ‰¼ÁèiZB8™EbæĞRÄ÷¡\ŠnáœRÕ¤C‘"ÌsNó_Ö¡÷£'ÔÓ3rdÂVîiDØÿ ëÔ>¦œ„œäÓ°®ÉÄ„¤Éõ4ØûÓª’dúš‘XíÔtôû¢ªÖ@İ‡†FhŞ=)***""\r" R"***(6ŠD6Øÿ 7ÜÓƒÿ ×¨ªJi\B–&r::SLƒ°ªQ3l~ãœĞÒ*2Ä´™'©ªQ±£üßsG›îi”U€ÿ 7ÜĞw­0z
\ö¦›Ğ}5‰)***""\r" R"***(Ö›“êh¦Ö„ã·åGŸZe"nÃüßsH$±¦à“GJµc'&Ç¬¾‡ó§ï†¡©*’DI±ş`÷£Í÷4Ê*¹Q7¸ÿ 7ÜÑæûšer¢°ñ!' š\ŸSùÔy#¡£'ÔĞ¢…vL²×ô¥ó}ÍA“êiwZ¥6MæûšPäó“P‡õ¢Lp3IDbu“şyƒĞÔ!‰É¥GzµfİÉ¼ßsJ²ûşuñéN§k©?›îh2ÄÔ>¦—qõ§ÊD¾kúÑæ¿­E¹½hAäÑÊMÙ/šş´	[¹¨Ù‡ğšMíëBL,É¼ßs@“=ÍB²zœÓ·Š´‚Ì“Í÷4y¾æ¡fÉàšLŸST¢U‘?›îiEÃŒš¯¸úÒ†ç4ùP;"È•ÈÍ81#95XK„Òı ûÒädCÿ × ±=ê5ıiÙ>¦š‹MÇûß­'›ƒÔšacI¦³Œ`®Q2a>(ûA÷¨2Ç€Z0şÿ R‰7¹ef'¿ëKæóÔşu Î)U±×4ıÃK<â:GÚ)***""\r" R"***(BO¥!AO–ìXäu?…Vìj”G™æ©@Í¶X{š<ßsPn?ŞıhÉõ5\„İ–ŞÔñ0=	ª¡ˆ§¬ƒ·ëO‘1>Ğ}éVr{Õc6)VaE?fÂÌµæûšÄ‚j?Ú”K’3K-"ÂÎIêië)Ï«y€tÍ9e÷íÚ—³2È”÷&—Í÷5_Í÷4àç±Í.AØœ9aÔÓ•ÀÕ1‡JQ)=M
Qe(3OY†ÍùUA&N2iCïPà]™qe÷üéâ^:š¦$ÇsO¾:Òä2È—¿?ÎŞ?Ug¹§ã5JM|áŸ¼:_?Úª`sš_5»š¥lî[Y¹àsKæ¿­VYzsş4ï7ÜÑÈQ?šş´«!=[õªşo¹¥[¡4ù ´²ûşT¾o¹¨`]ÍëB€Õ‰ÄØÿ ëÑçœäU|ŸSFO©ªQE$‹krÏ¿hÕeû¼ÒÓåAd[[…õëR­Ç¥R^ƒéR+ÇZ9BÈ»öƒïGÚ½Uó‡÷çG;¨å‹_h>ô¾yÆIıj§šş´	œUìÙJ%¯´z>Ğ}ê·›îhğsT U‹?hjx•»ŸÊª‰Ktåvn¦©A‘cÍ÷4¡ÉÔØS–lbŸ(	w©WÚ9ªÂlœb$ã½5
ÄşkúÒù¾æ«ù¾æ•e÷üëE	hµæ¾zÒù¾æ YÉ¥Ş}>@³&`ç&œ³’pIªûÏ ¥0äQÈ;2È˜ƒM/Ú½WHûÔn>¦­@Ve•¸ÉÁ&œ'¹ªÁıE=]Gÿ ZŸ³‘e&Ç½;Ïö¨œĞÍÎA§È&¬YYxëùRù¾æ«	ş”ås×4ÔDYY[_5ıjf#9§ç5\©’dÁ‰Í9eoâ5c	©)¤˜4‘?›îiVCœ†üê:)r†„ÂWÍ=%äsş5\1“OF§–ÁkìOæûš<ß­E¼z7¯¥.På&[¡4ªØëPù€tÍBzf©Di7ƒÅ(>†«îoÎœ’„š*×'V òjUŞ«9àş´õ-´sùT¸±ò“o†®qšXçRP ;"e—ßó4¦r;Ô!Áÿ ëĞ\?•dKöƒïNYÉ9&«ï†”HÎ(ä"ÒÍ“Nó}ÍVI¹Í;Ïö£”9IüßsNY‰éUÖPzÓ¼À:fŸ(r¢À”ãæ?•\÷5¹næŒŸSUË¡J,²õ4å÷5XHÀc4åvÆsSÈÊ±ieùG?•9]ºç5]XíëN°ïG#"Ò³c9§‰3üUXJøëR!'94¹Y|ßsG›îjŸSFO©£Ù…‘?›îiVN?Æ G¬2(ä±-jK¸úÒ®sÎzT{×Ş—Í÷4ã³%ät4å¦¡OBiÈIÎMU‚Ì›q=õ§õ$t4á'¨£•1rÜ”Hã4õ—åÿ 
¯¸3Š‘\Ar’ù¾æ”1#95ñèiÁ›f@Q&Ş=)***""\r" R"***(8OÏ"«äúš’Ÿ)j$Şjö4¢Lÿ ¨(Éõ4r‰¢ÊÉƒÔZw›îj²1È­<7<“O”,É¼ßsNW	ÍA¼zzºú~Tù4)8p àÒy¾æ™GcE
%('¹§,„Iü*,ŸSN_»V¢¬©ùØ¥2**PÌ;Õ(•X—yôğÄt¨‡JPä{Óå®~—'M'4´‘Šü=3ôŞa¾gµòqŠ]‹HÀ/"«™Î8:RïoZ{zÒ‡èL\Ì~öõ ¿Å7zúÒ3ÿ v©nCºsšiq4’zÑVdä;Ìö¤Ş{q@ÙzÒ¼SMäQERwlPäuæŸæÿ µúTtV±I«’İ‰§O9©”Uò¢™KpzQ½}J‰ŠEbO&‹XNV&<ŠÀÎ9¦*äóN
Jd¹’)Ü3Š
‚rE0:]íëAM;N€í´×s’;úÓw·­ZbædË.\{Rù¿í~•°#“Í/Z¤„äJ®qÍJ¯Ç&«‡ÀÆ*D$ç5d9"O3Ú3Ú˜X
O3Ã@¹É„J&lóPù£û¦—Ìö NDÆb:O9ªíëFöõªåds“¬ŒÔààõªÛÛÖœyÁ¡Ä\÷,o_ZBüğ*-íëFæõ¡!6LuïFõëš‡{zÑ½½kDI6õõ£zúÔ;ÛÖ9VC»&Wşñ¥b£ƒéÒ¢{Óª¬C3)w·­%r±]Wì:ÿ ºi´ZiÚBïoZr99Çõõ¥Wşé¦.btàŸÎ—Íÿ kô¨Lœt¤ŞÔì'"È”@¥àc8ª»ÛÖ•\cæ<÷ªHfZóÚı(óÚı*¸c)***""\r" R"***(.öõ§È+²À”À©LûÕaÈ§—P3š%È•¥ííÒ£i9ÆqíL.M'9ÎjÒ±MïoZ7·­G½½hŞŞµZÌÉ7·­(Z‹{zÒ«y4í`æ¹(††“=?:e#68Å
÷%±L„£Í8ÈjŒ’zÑV•÷‘ —¿¥.óĞTT	Bñı)ò"l—{zÒy¿í~•™şÕ&G¨§Èˆ%óÚı)ßi÷¨h«QAk“‰É¥óÚı*¿J]íëO•Ñ?œ1Œş4ˆèjÄŒøÒGJ9QœL{šQ0Nj)***""\r" R"***(íëFöõªQD“™‡cG›ş×éPolõ£{zÕò’Ù?›ÆíÜ})DÃ½@\ãI½½j”Q›mEÆ3@¸$àT
I4¹äQÊ‰,	²3»ô§-ÆúõXH Æ)***""\r" R"***(;zúÑÊ…tYóÚı(óÚı*¿˜}OåJ$>ÿ •>QYù¿í~”y¾ÿ ¥A½½hÜŞ´ù¡?›ş×éG›ş×éPêJO7¿¥>@»,y¿í~”y¾ÿ ¥WóÚı)CõJ!vOæÿ µúQæÿ µúTÛÖíëT dşoû_¥hõı*)***""\r" R"***(íëNRHÉ«P/›ş×éJ9¨©w0ïG(	›4ÿ ´ûÔÔæš\ö§È“q‘ŒÒyËU÷·­Î1ßÖŸ"%¤YY8£íªâCÜRocĞÕ(YûO½*Ï»½UŞŞ´å“Õ¢‚ÙhOŒÑç-Vó¸ëúR4™ïOÙ¦)***""\r" R"***(LÃ±£Îÿ kôª›œôşTåÎ9ëMA"‰/Ê>j_7ı¯ÒªaÆh{Õr"yK~oû_¥QĞœÕq/J<ßö¿JPùQgÎZÊHªŞoû_¥oû_¥W,Eª.y¿í~”«)Ï)***""\r" R"***(TÖLò[Šxq5<‚»-‰y§$Ç±íUVLS–m½OåK”wl¶&=Í8\ ¼U_8¼RïoZ9
EŸ´fœ&=ÍSóÚı)É)éšNj‹^oû_¥9f;x9ª¢_›Ïµ=eÀÆiªcW,yÍOYÉU_7ı¯Ò•dÏ½Í¶²±§‚)***""\r" R"***(VYsïNŞ¾´ùš¹`NM/›ş×éUƒ¨9Í8L§€)ò“ÊÉÄÇ<ÒŸç5VWÉàS÷·­.]JQ&æ“Æ«#¯4äsÚš€¹Ki/æı)Şoû_¥WW8Èâ7ı¯ÒŸ!\¥Ÿ=hóÀäUc(ìhóÚı(ä+•ÄäŒŠQ/©ı* rFA§‡l{Sä)E2Ø™±NAæ«,„)***""\r" R"***((÷£”|©·¯­Àäu¨<ïö©<Òx5J"±?ÚqŞ”LIÃTÀä<ÜœV¢4›,y¿í~”y¸ş/Ò ŞŞ´ooZ®T]‹I0ìqRG2óÅRBNriæOöj”‘sÎZ<åª^aõ?•9\c“úSöh”®[ñOó•Md àÂ%ÀëŠ9
²,ù¿í~”¢eïU„„ôoÒœcïU¨	Ä¶&\ô§yÍšª­¶¤Ş}Z¦+2o9©|ßö¿J„?cJXzÑÈY“¤½ëNóÚı*ºsOŞ¾´r‡+%péOYqíP	€âœwâ«”N%¥›#š<ßö¿J†>ôêT+\KïúSÖQ §§İíd
*äë1Ú1OW=MBŸtRĞ’eò¢ÊI‘R,¹=sUW úSÕ³Ã®UĞN%¯7ı¯Ò7œnı*-ëë@u9£•“ÊM½½hÀç5“€iw·­K‰j$ŞsR¬¬Çöõ¥YzóB€ùYa_ûÆœ¯ÇÊj¿œO^)ë!“úSå*1îM½½iQ¸Á<Ô>oû_¥\¿¥>B¬‹!ˆ§,¸qíP,‡ğ§+Œ|Çš\‚q&gÕ —ï~•[zúÓƒœphå@‘c{zÑ½ºæ«ïoZ7·­…¨ù¿í~”	sÑª0M(Ôr•BÏçNÑªº‘sOŞ¾´r0å'Y<šzÉŸz®²öëJ%# £“PåEŸ4€9£Îjdf§+ñó¾[!Ù,ŒÃ4á+Š…\ãå4åq˜óŞ—.¡dXY›á/«~•\1Ç”9ïO,‹i+0©c˜ÕM\ã‘S!'©¨q)EX±ç6iÂBz‡zúĞXA¡GBœ&İéË68"«ùÍ@•‰Å>TG)kÎZ œU÷·­*9“Bˆr––n>j‘fãæª›ÛÖ®Ş˜§Ë r–|å¥ƒĞUmíëFöõ¥Ê.TYó9&ÅT0â²ddŠ9Xr¦XƒÀñ/j¯™íOp8íNÈ\¥•Ÿ)Æ_CúUPàõ§—=ª¹GÊMç5V&¡Äã4ú|¨|·&Y7&æÿ µúUq‘NsÉ£”\„âPx§Ç'Š®$ÇCúRïcßôªQ4P.$ƒsKæ{Ut`:š]ëëUÈ‡ÈN$#)|æªû×Ö€Àô4(!8"È˜‘ÉÅoû_¥@†œc9«åTYYx7oJrI¦«‰:TˆE‰)***""\r" R"***(ÆÇÀ§šfóè)ÍĞı)•ø*½Ğ9¬.óè(,O’ŠbæAE! u¦–'½UâC•‡n_QFG÷©”U&O;\
dS)C0*·%É¦—Ç Ro>‚òsM]Ì.öô¢OQM¢´LWcËu¤/è)´V©è&ÅŞ}Ï ¤¢­\‹±K0hN¿…% r)’Ù(b:Q¼ú
b±'A›–£¼ÃéI¼ú
Jk1šW%±ÄäæŠE$ŒšZ¤¬.aÁA&”ıi™=3AÏjÑäH;
“š‰z¥I‘ê)™ó1ƒŞ-i<ßqG›î)j+Ü]ƒÔÒ2(äQæûŠîã"š¸\J(¢´2
]ät’Š™¼ú
7ŸAIE0àç¸§‘šŸtU$Åv(8íK¼ú
J+HØ.É)ù¢™EQØòÀ¦ùŸJkd/Ze ¤KæØ ±=j psNó=ª•˜›J¯Jg˜})7ŸANÈ†Ù.ñéI¼ú
j±n´Š«16;yôàÀH¨ù<ƒKV•‰rDªçR‡Å1>è¥§mçdªíÀ¥zÔAÈ£{z
VBæ%gôÛÚ’‚@êh°›yô¡óÁ¨ÌƒÒ“Ì=±T‘DÙ¢0!ãš‡yô¡ıER"è˜MŸJFşóè(Ş}i‰»$Ş}Ï ¨÷ŸAJd=…]7qûÏ ¤'¹¦o>‚”)a’Ôì…{‘ê)i¾_½8PÃƒúŠú
i8¦o>‚©"[$Ş}Ï ¨÷ŸAFóè)ÙÎÉ7ŸAFóè*?0ûQæÓYäÙ&óè(Ş}1_'š\QZ(t<8ÇCI¼ú
ip=é»Ï «P!’‡=Å9YréP‡=éw3š|ŒM\œÈ âIî*'`sI¼ú
j5rÇ˜OLR‡õ'»ÍW'b?Ú 84ŸhÕIêi2=ER€‹"pN)|Ğ:â«n´ªÜç4rX	šlŒb‘_'“Ôy¾â­@	²=E(p½¨<ÂzbçĞU(cÍ÷y¾â«ï>‚œÏÔ ›Í÷åŸåéUò=E89ŒU¨?ŸíKæûŠ€?¨¥ëG"2mçĞPd#®*3/E0Ê§½R¦æ\zRyã8¨ŠF¤ÎE5LVorÀœwŸhê&GP)¬İÁÍZ…‰v,} {Qö‘íU•‰84ê¥Ùô¥ó}ÅWE9I#šiag cŠ>Ğ=ª³8i7ŸAV ˆ{—¹ç"7ÜUO1¨ó_ÖŸ³oÍ÷y¾â«$g&ŒŸZ~Ì>o¸£Ì'¦*¾óè)UÈ=±õ¥ìÀ°²Üâ¤Y€9$U0ƒõ 8Ç4ı‰i²Ğ›4¾o¸ª¢P)ÂlúQìÁ"ÒJ;bæñÔ~uSÌjxb){2‹o¸¥ÿ UWŞ{Šr¹Çš…‡vYI*EsTYnqS,£o#õ¤âR%Ş}80#9	”vÇçFóè(P¸Ë"O_ÒŸæûŠ­’:Rï>‚KÌ±æäR‰”æ«ï$àÒäzŠÒ-%ÀİÚöUàÑ“ëC‚‹hÔä¸¨ªjyäö©Ç4ùPrÜ¸&QæûŠ¬’g;i|ÌuÅ>B”KAÿ ëÒ† õ]d$qúÓÃdd‘BI¬ƒ?*p›° “	qÜUr!Ø°$>”ÿ 8‚µ\OÇJ¤f;2Ï›î(ó	éŠ¯¼ú
rÈsOÙ ³'Iæœ)ÎGçPo>‚çÒŸ $Ëo¸ J;‘P+äàâ—#ÔSP¹M2ÊÌ@/›î*¶à:7ë@r¿ızÑBÄ´Ë>o¸£Ì>Õ¸#$Šz¾ªä¸$LÉåsŒ
„6y$Sƒ8§È;&É™?áR	:
¯¼ú
x'\ˆV±ef' §ùşÕTI´ıçĞSäb'dãàüóŠ®¯ëOó3éK•Ühœ0 Î—ÌúT
ÄœS äSä‰•‰84ğÅj“çNŞ}>AY–cŸ ñNóıª¼n9ÛNŞ{Š\—'•	³ÏëOY°:UpÀò>´år(äµ-,ÿ /JQ)=ÅU7jpb@9¦ U‹‹/‘Ò•dÍVRp9=)é&3šÌ´d#®(óÔTBNëNÈ9¥Ëa¨“‰ 9Å(›=EAæoÎ—ÍäÑd_+'ó}ÅÏ ¨‡°§$½©¨Ü|¬™[=qNB*!ì)U‹u£–ÁÊMæûŠ£¹)e$@:Ô‹*`U0HéR+½)Xj)–|Ôõ§	øàUMçĞSÃu£”¥X3dcÒüñúÔ9>´»Ï ­GÊJ“ŒSÁÍB¯Ï#½?yôùdL²`óNóGr*rN)ÔrØ,‰ÒAÖ¤¦«'_Â¤C×&—.ƒ·BÊ²œQ‘ê*ÄRï>‚¦Ì|¤Â@¾aÏJ…K“ŠPHïG).6,,ƒá*çš~í9X)É¦ã¡J(²²ddŠ•%ÛÔUe~9 ïTò—ÊXŞ})<ÃíQù¾âƒ&F2)Y ”w"œ&P8ªù¢”0‚*”S‘cÏö LIÀ
¾N)ÊØ<c¥RŠ@’'IOr)é62*º¶zâœÁœGÊ¶,yşÔyşÕ˜}©ÊI4”P¹Q0‘œSÖ_—µWÉ)***""\r" R"***(=s´sO•H˜HO#¢CüU¾)***""\r" R"***(8r3ID,‰ÖN¹Ÿ¼z‡ ô4ã'<
j"åD¢A”ï7ÜTÉ8âÏsT 5bepzÒäzŠ…	È§ÕÙ!r’+`äS„¢¢S´çªÙëŠ|¥¨–<ÃéI¼ú
bs“N£”®AêÙ‘J¤šœŒzU$ƒ—R`r3E09§ƒ‘š¤†¢9_¤Y~aQ„ÈÎiÕVCà§u<L¦ùÔyÕüõv}“êBBŒ“Iæ{R<ƒñM6ÀÍ1IMó=©“ÓŠ¢‡€SŠRT2>ôê¤C“
i|b•—qÎi<¿z¡s&ÆyàAß/Ş€ÛxÇJ¤ÉrMó=©Àäf£­".k’«míJÎ ?Jˆ6¤$µªbnÃ‹Â3Ú›HNjîÈs$éj3Ú3Úb™:§8¥^*¿™íJ­»µRÔ‡"Æõõ¦±ÜsŠsô•I	»’«mÅ/™íPÑTMÑ7˜=)Àäf¡Zp9«W"R&ŒP¼Tağ1Š<ÁÜS"÷$.;
äãqØP'§fG15 àç$t4»ÛÖ„Ø”Ñ/™íG™íQ'©¤«W"o3Ú3Ú¡¢­&.ro3Ú3Ú¡§+qó«0ç%#5"}ÑPÜpr#4Y‡15&õõ¨¼Ïj7ûUE0r'ó–—Ìöªşgµ:¯”bRùÅ%FiŞgµ;"9­°ìŒcß3Ú3Ú©!9¢›æ{Qæ{U%as‹Ò‘›'¥08Ç4yÕi\‡!êÛF1Kæ{T$äæŠ¢E…™@Æ)Şf{U`øÅ<ŒÓ³17™íN™çš„>1G™íM@\Åƒ'1LŞSQ0:S|ßö¿J|†m²}ëëFõõªÆL·OÆœ²ò
|‚½É÷¯­8¢ó=¨ó=©òÛaP1MB¼SšPz¸Ä/aå€ã4gµGæ{SIÉÍiÈKw&3È§	TUpH9¡øéŸzj›–<å£ÎZƒÌö¦4™÷ªöh±hÌ¤b˜\vÉŒö¥$µJ$·rc($RyËQ É¦³ç Æ©DDşrĞ% ª¬vóH$ äÖš-â—zúÕE—'¯n”ï3Ú¯’Ø•d
kÊ	È[Ìöıhó=ª”@±æ{Qæ{U3Ú3Ú©D!Ö‚ãµVó3Úƒ)#~µJoBÒÌ¸v¥ó–«FiÅóü5jÌ°d<TeÇaQ™	íM$µ¢€yÔ	Hÿ õÔ4„…4r?™íúÑæ{T×Ö3oJ9GfYI@ê)|åÆqU<Ïj<ÃéV£p²E¿9hƒĞUO3Ú&éò³æ{S–eUO9iD ŒO~rúQç-Tó=©|æ©¨ ½‹^j“ƒJ_ŒúÕA1îqO2`dŠµîäÄ€2i¦Nx˜ÁÅ4º“’j”DNdö£Ìöıj)***""\r" R"***(ëëFõõ§Ê&®Oæ{S’P:Š®²*œÒ‰Aè)¨”±ç.3Š<åªí&)…ÀéWÈ+2ßœ´yËUŒò)ÊA9@³EŸ9hó– . ãš<Ïj¾AÄËGœ¦ªyß­g·ëV©‘ÊË~rç¥rÕj)û1]––qšx•OM	È©ô§ÈŸ3Ú3Ú«ùÔäqŸÂ“ˆBs‘úÔ‘ÈNsUÖEZQ(=O-ÊH³æ{~´å˜cš¬%"œ²dzÒp(²$)ë'Ê>Zª%#”å“#=}éò³æ{SüåÏJ¨% ğ)âuÅ.B•Ëræ—Ìöª‹&=©şgµ.TÊÔ±æ{~´yÕ pzĞ$Psš“,$Ÿ7J™íU¼å£ÎZ®DR‰g9Å9ãùÕA(' SÄÃø¨äÔiceÁ9§o_Z¨²³Pd àµˆ®WbâÊª1NÚ©	€ç4á94ı˜ÔK›—Öœ&P1TÖLŒõ÷§o_Z|¥"×œ¹éRyËš¦&P1NY‰äÕr”â^ó–9j§™íG˜;Š9¬Ë~rĞ&RpTó=©DÄp5e¿3Ú3ÚªyÍJ²’
®@³-yß­9$÷ÍU‘ĞSÖL÷Í5å¹h8=iÊà9ªªwâœªQ¸ùK!ÆyôqoZ¨$ ä
zÈHÉùEÊË`¸Í88î1UVV<SÃ®95j:
×,‡LóÍ?zúÕ1 )***""\r" R"***(?ÌöªpRÎõõ¥ çúÕ_3Ú•dÒ— ZÅ¸åºTgµTIG¯¥?Ìö£+(šzÈ¬*˜qÜSÖ\ûÓäĞ,ËŠé‚@¥ó=ªª¿÷M.öõ¥È·,‡SÖ0ëUc'Ï9§¬„uüérØ9l[YŞ/™íU–LŒâ”8î(åE±2ğ1O™çš¨&P1NY1íK”®T[ó=¨ó=ª¿™íG™íG(ÒE€ù8Å=N&ª¬‡8õf-É¥Ër¹K;×Ö•\ÅW¥E¶$ZZr89ª ƒÒœ¼Ğâ;&Yó=¨§­@´o_Z;‡*,o_ZQ*Š­½}iË Ú0*½˜íbÈ“=©âeP8î*A'…,¯¡Ôµ[p(ó=¿ZµŠQ-ùËé@˜€*¨”Ô«)'ŸÊŸ*‹‰ Ï¿¥;ÌöªbRL~4á1Ï"Ÿ ùo©me
rE8JAU#™sÓµKËéIÀ9lYI:óšw™íP	8¤ó=ªyÒ¹m$éJg‘UÌ:R‰ŒÓå%Ë« Ç”8î*ª»œÒïoZ\€¡bà™FJ²+sš¢¬@àÔ¨ÀwúRå.Í–‹¦x£zúÔ^gµı¨ä).õõ¥G]İj3Ú! QÈ.DË;×Ö•d ç]e'ü)Şgû?­‚qH±æ{~´äqÚª‰Hè)ë&{æ…X³æ{SÒN:UO3Úœ®HâŸ"[–÷ôõeÚ9ª±„Ô« Ú08§ìÆ M½}j@ëµ[Ìö 8ïO|…¡*À©<Èı*¢0É§Õr"yQ`H™àS¼Ïj¬ŠPù8Å'†‘e$çîÓüÏj¬ S•·b‹jW"z“ùÔ ƒĞÔ!È§+níV(¤YN¼S¼Ïj¯æ{S•Ø)òõ4ådá×½=]q€0*¸sÜS•Î8¥d.]K+ ÛÀ§ƒ‘š¬ŒÀjE“:)Ä°½Òœ1Üf WsOVÛÚ­DO€¨¢°üæ›>±iÉ·#Ö›J§4î‰rĞ}İãĞÑ¼zjLf:‘›iÆ)7CHÄ‘V›¶#1' Rsè?:…8Å'˜µ¢w%¤/>ƒó£pÎ)***""\r" R"***(&ñèi§“šd»u¦ùÔŠ@94•¬l!ÁÁëAƒ4ÌAA`)***""\r" R"***(Y.CËäcÚMâ–šl‡$R9 qLëT‰m2JUm½ª.ôèûÖ‹b%VİÚ–›zuZd90 c<ÑEQ›c·(-gµDÄ“Œ÷¤«H‚o3ÚQ/Aô©O Ó'˜(5$œš+C>bo3ÚşÕ89§3¼zÒQWbO4¢Ìª*+D¬72_9hƒĞTTèûÕ+‹˜“Ìö 8Ï"›EX®ÉQÆ1úÓ‹Õ 89àø\ŸÒšC¹'™íG™íQï†ãĞÕZÁÌMNó=ªvñèiäIæ{Ry£û¦™¼z7CT¹‰<ßöhó=ª=ãĞÑ¼zµ\µ$ó=¨ó=¿Zxô4o†Ÿ)<Ä»×Ö“Ìö¨™óÀô¡Tš¤™Z’ùß­*œŒâ£ KT“L›±åÀ¤ó=©›Àã›Ç¡«³'™íN•p­o¹­I¹)$õ¢¢ó}Ío¹ªäaÌKFåQ“×Ö¢ó}Í@zæ…ÃÌœô£Ìö¨÷CFñèj¬É$ó=©ë.{æ ó¡§n š© z™@ê)­.xíéQo†¹Ï©"¹/™íG™íP’OSH\ŒU¤"3Ú3Ú«ï†ãĞÓ³+˜°´…D†’zÖ‘Š%»“yÔyÕ)***""\r" R"***(“ÔÕY	²VpG<SK¯jŒœsI¼zj$¶Ù'™íG™íúÔ{Ç¡£xô5I”ºã­'™íL=Aüh,ÁªPşgµ*œŒâ¢Ş=)***""\r" R"***(Ç¡«P`N%P1Gœµå4`ô5\ˆÍØ±ægµg8ÅWŞ=éÕj¶Mæ{Qæ{T‡­&ñèjùEvXó=¨2Ô~µ_xô4¡Á4rÙ7œ¾”	Aè*QAeèQCM“ùÔyƒ*¾ñèiAÏjµ‰Œ uyËP– àÓY‰<t«ä@Xó–9j©p(S‘š|¤»üÌö§‘š¬²b$Säd–<ÏjC2àâ ó¡¥g¥R…Ày¢3Ú¡$´Uò8—®)œô¨•ˆúR™uÍ
l“Ìö JGAQ‰ŒàÒ†ST¡a^äË.{æ—Ìö¨2?½Ap*Õ1İ”Q/p*¾ñèiwCMBÀÚ,¬À_9j°9¢­A¶Ë>rúQç)â«S·CZ(!jËgµ@H¨A#¥(vÏ&«•)`L§ §,€‘U·¯½9n£9K>rĞ% ¨7CFñèir”‘grúÓÑÁêÕSÌôõïN™¢EëëNY9æ«Üp~9©ä,	9ÏJ:ã#š§¼zxrG@Eàõ§‰0ªªÉïO)rŒ¶&\Ò™rzUUuOëOó½>DRDûÇµÇµ@Z|…¥rušŸæ{Uec3Å;#ÔP£aò“ùÔä“Ú«dzŠr8u§ÊÆ¢[Yºî¥ó–«£Ş¼SP4å'ƒÚœ³(¨ÀààÕr åDşhÆJ<Ïj†œŒP 2ebGz’9¥VY=*@àûSpÍñèhŞ=)***""\r" R"***( LiŞgµWŞ=)***""\r" R"***((`hå3Úœ3Ç¥W§!$òi¨cÌöıièãjº¹É5"°^´ÔF•É|Ïj<Ïjxô4¡ïUÊ>RUbyÆ)VN=}ê_Ö®6Š¥µÉÃ¶:Ó•ÕmãĞÒùƒ¯5j#åEÍâ—#ÖªooZx$tªå¸¹K àæ² y[ÌníJ%Ç­'r–ÖUÏhó3Ú«,¹<ÒùƒĞĞ¢
6-#ŒçÚ¤È=êšJ	çÒ¦Y=OåMÄ¥Ê´ålb VÏŞ4¹¢£”j%€àsœSÖOÿ ]TÈõõqM.D—-3ÁjMëëP¤ƒm.ñèiò•ìÑadàqÚ¤YTöª‰'"°n”8‡*-ï†•d ä*
*yC”³ç'­*L›¹TÓÄ€SPAÊZó“Ş9;U_8ûÒ‰I8Ÿ³H9K"Pz
Pàjºs“OVÖš‰j	o_Z7¯­E¼zBß6E>A´YWÅ=\cUOSÏ­H²9çéG)E3Ûõ¥ uªÛÇ¡£ÌÏ4(V-«mê)|Ïj®­ÉÉ©7CNÌ´‰<Ïj<Ïj``{Ğ\Š,ÇdH2=})şgµ@ŠZifN­¸ã"1=ê²N¥HŒÜœÑÊÂÌ´®HÀ¢™iÊÛ¹ÅO(‡+cƒR#ŒúÔTçƒG)¢E•màR‡­@3NiêÃ¥Ê€°$àqJNqÅDb”0n”rØ¨¢ÆG¨¥Èõªãƒš‘\g4ÜR¤”äÁïŠxô4¡Á8£”5h–”9j,ŸSNF$àÑÊO+&ôàQzT=)ëä¥.[
Ö$S¸gä9¦+ 0iêà
vE89©A·P‡®6éV’O3Ú3ÚšFh¢È	¼Ïj“ÌöªûÇ¡§håB¶·&ßíJ;úTa§)ÁÍC¶¤Ñ°ÿ 3Ú 	Å.O©¥aØ›Ìö¥¥D„“ÉíRGŞšµ)"HûÓ©ŠÁzÓ·Šfœ£Ó§ãR"ÿ D® §â‹	'r`øÅ(pzÓîŠZ³&p8¥VİÚ¡{ŠzÉï­R@¢|Fx4`zPNM5˜cƒ_Í§¸Øê2SQî>¦Œ“ÔĞG0ıâ“xô4Æ$ŠnãëZ-EÌL\Œg5_'ÔÑ¹ºf´AÌJäÁíIQå±Ô»ÛÖ­!s’(ÏZwÈj„1­875IÌ?rwô£rz~•cĞ~”™>¦­#7"bËô¨Üæ›“êhÉõ«JÄ¹\4ğàœS(ªH†I€zŠl€;ö¦äúšc©«QìÔÓ“ã5JOSŠÑäN¬­#H3ÃTA·¹¥«V3”®J®1ÉÍ.ñèj‘ĞÑ“êjÒ&èòsE l($Ñ½}jˆrÔ‘z¥<¸#c)***""\r" R"***(IL‡  œĞNM5˜À5d†ñèhŞ=)***""\r" R"***(0²ƒ‚iÆ8=êì€“xô4yƒĞÔ9>¦œ¤KS³'˜”0n”õ “Po£Qæï´…ÌÉ÷CFñèj0xÑæµV¢äûÇ¡£ÍOZƒÌŞ4¡‰kEçDŞjzÓ‡#5óOqÖŸ(œÉÃ)ïùÒª%oïvõõªP'˜vóœ)|Ôõ¨Ù—oZfõõªI"['óSÖ1OJ€2“€irGCM"y‰·CNÎzT
Ø<švğ:5RÑ‹™“‚€zÑ½GAPyƒûÆ0xÕ%qï†ãĞÔ`şñ¥O š®V‡“šBÀw¦— ri»Ô÷«Q%±ûÇ¡§T[×Ö”>z5]‰º]AÅ'˜´ÓÉ4Ö`G´'˜“xô4ô	b9$Ğ$ÉÀcUdÄŒärI¤ó}Í0¶&“zúÓå(™%^æ½qj¾õõ£x© 'Ş=)***""\r" R"***(.õ¨<Ìÿ ¥ÜØÆiò‰ÚÄ»Ç¡¦“Ïşq¸Ğ	õ§êfİ‡ï†”r3QÑ’:µs«c©¥.1š„±94`şñ«Q'rRÄäÒy¾æ˜pëMfÀ<Õ¤»Á&“xô5O©£'ÔÕ¨6ñèhŞ¾õ¶&½}jÔP›±)|îıi<ÁïQçŠkIØ¶)ò“ÍbmãĞÑæ(ëP†'£2}M;2y‰¼Å=(ó¡,GV¤ó÷Zˆ­rÀ`işjzÕO0xÓƒß5j7$JÎ Æ*ibI4›×Ö‘˜À5¯*0¾o¹¥YGzˆ²ƒ‚hŞ¾´ÔBäşjzÑæ§­A½}hŞ¾µ|£æ'óô¥ó}ÍWŞF¥ó2>÷JjÌÉüÁïM,Iàš‡ÌŞ4yƒûÆŸ³bl—ŒóN ÍAæï7¯­R¦"5=hó—ûß­@ ázš¥…rÀ—ız{J¸<Õ_3ıª<Áıê¥“ù¼õ4y¾æ Œµ?zúÕ{0r±*ËÇQøÒyÍD\cå¦™9ûÕJóù u&œ®;œÕ_0xÓÖCÜâ«“A6Y, g4†Ej#!Çjiu=M5ù©ë@vÍVfçƒJ$`:ÖŠ [YWš_5=j “#–£ÌŞ5^ÍÌ[óSÖ"“ŒÕO0xÓ·· ¦¡a§rÙqÙçFÿ ö¿Z­æïQ&xİG³‹À<·ëN®x5W'ÔÓ‘Î@©å)+|ßs@“'ïÆ 21áM'™şÑ¡BåÅ–@:µH’ÎsT„ w©rZ~ÌÑ+Ä˜õ§	Tj¢Ë¸gu89=ê\,)***""\r" R"***(¼Ôõ§¬Š3U†94¢AÙ©8”·æ§­(“ÜÕQ/`ië.3G%Æ•‹BE=*MãĞÕ@ê­Iæï,Ri<ÁïG›îj¿˜?¼iCäà1¡Ä¤Ël
O3'©bsArhQ-&X(ş#ùÓÒEëš§“êièÄÓå*ÅèÜsK¼z¯~j_0xÓP*Å¤‘qÉ¥óSÖªù£Í'˜?¼j”–…Ğã³~´oÿ kõª‚V# ÓÃçø‰)***""\r" R"***(Få¥‘x©<Å=)***""\r" R"***(TRëSFÊs“O•‘wCFñèjŸSFO©£”V&Ş=)***""\r" R"***((qµO©£qõ¡E‹ÿ ÚıiÈùïøÕelM<HÈ5\‚QL²®£©ÍH’š¥çjx”‘É¦¡bÔl[óSÖ1MUó÷©É(#;¿*®A²ÆñïKæ}j&N7r8+É§kîÉƒ3“OVÅ@<iCUÊÅfZÿ ^Ÿ¼z«¼­?ÌŞ4r±Ù“ù‹Gšµpxİ@eé¨\i\°²)èiÊüõÏãUU×wšz¹Ï48Ø¥Ê¾O§¬„uâ«¬óÚæıê\£P.	8<şto>¿­WY¸Í.ãëG*+”\ç95"¸­VY8äâ”9ê)***""\r" R"***(¬9K«"ŒÒùƒĞÕUbGZz¾xİSËb¬Ë
Ã¥Vã8ªÁ—šp”O”\…½ÿ í~´…Ï÷¿Z¯æïRùÃüŠÉr0úŸÎœ¬;çUÄ¹8È§£.î´ùEÈO¸“J® óQo_Z7¯­£ä,¤‹×4ã"œÕ@àtjz¸=iª}GÊËjzÑæ§­A½}hŞ¾´ù”Ÿz™§ãïUpÇr°ÛÉæBynÉÄŠ	§«ï_ZUCG!J%°àÓ÷CUVOCŸ­?ÌŞ4¹C”±½sŠ2=E@ŒiUˆ<š9F¢‹
è3K¼z†<=jLbR•‡†Éã5"3…Hš‘ÍRŠ°ÚV,G Æ)ÂLzÔ(Àu4íëëKZ	2zšz¸ÇZƒzúÒ‡QÉbÑidL}ê]Ê{Õea·“Í=\õ—%†Ò-+:ÓĞœšªqÁ©OCŸ­'’±`uæ¹?»úT`şñ£ÌŞ4r‰¤YV\çô§CĞUU—²18&QY2=E9XÖ««`òjDeÎsCZ)***""\r" R"***($ÉòCOPCU÷Ñ©ë&:œ}(Q¸š±5#¡¨üÌÿ §+ 94ùDH¯Øşu"¸ ¤ã4õ`fŸ ¬‰ƒpiëĞ}*“)***""\r" R"***(<IÇŞ¥Ê‡dÉFÜóOÈõ_ÌŞ4àÌsUÊãƒšxpMV18Í=XƒÉ¥È¹aİÖ‘ê*¸u9§,ªN	§ÈW+,+ zÓÒEÉªÊÀıÓOVşñ¡G %©d0=)j”ö4õv#$ÓPIfI’:’&©¨’94´4	;“ù€t&7ÜÔi÷E-%D®I¸rj@A8ÍD@ëKT¢R‰ğsĞŸÒ›ŸOåJx˜Y×ó2g§ÌÇnÛij<‘È ±#“U©/aÎÀŒM¤Èõ¹¡ªLÌ(¤Ü¾¢— ô5´BáE´Ç<õ­S±)***""\r" R"***(Ü}Rw!ÈyeM×Ö™ERW&ãÁ¡¥È¨óRU‰»Î(¤'4gµZVDsŠäÁ¦–'©¤$°Á4˜>¦´Âs¸¹ dô¨¹8&œ/JzåpQ´c4ŒX?•:Š¤ÌŞâ.qóRÑEiÌÜ¬Q‘ëFAèjˆrc× úT€ƒĞÔjF#¥-4®Hö gµFßv–‘Eh^Ã0})***""\r" R"***(¤RïoZÁ5aÏq(¢ŠµbnÂŠk6:³÷\lK˜ê)2=E.AèkHîO0S•€&›EZvaû×Ö”KÇ)***""\r" R"***(úTx>´U‡1 ·CK¹zŠ”¹íM+ä<M&õõ¦–'‚i*¹P”‰Œƒšs?)¨A#iw·­4„İÉU¹ù.õõ¨w·­ÛÖ«”–ìM¹qœÒ3œü¦£VÏŞ4ìZ¸ R{zĞ³É¤¦³ğjÒîH\ãŠMÍëQïoZrœŠ¤‰lvæõ§Ôu%Q)***""\r" R"***(¤)sM1˜cå<Ò±À¨Ø2*¹EÌ8±<HE3{zĞX‘‚jÒ(y	¤Ş¾´Ê+D‚ã÷¯­.xÍGE>T>kŞ¾´« ºÔy´™¢ªÄ¹‚¿xõ¥Ş¾µ ~Á©êÜrj”Hl“zúÒõ¨²£¡dzŠ¨ÄbSÈÅ4„i´Œp+HÄiÜy(˜YAÁ4ÒÌx&’­@\Ã÷¯­×Ö˜qŞ“#ÔU¨‰²MëëFõõ¨ò=E¢©E\d=Ÿ Ó€õ4×äğ{TlÄµQV¢q ô K“€Õöõ£{Í>D’$Òo_Z„¹íJ€j¹r]ëëJ$$ğß¥Gœu4n´ÔVK½½h,HÁ5›î)7“ÆêÓ”VhyeÒ3qòšc70Í4»õjm	7·­ÛÖ¢ó÷…9Xç“UÊ!û›Ö”ÉÇJfG¨¦¹ëÚ´ŒSb¾£üßö¿J<ßö¿J‹#ÔQ‘ê+ND2upG&”²õG­.ò3øÕ(6õõ£zúÔaşğ£Ì?Şı˜–\pi¥Ÿ×ô¨ÖOSšœöSTÄØó![ô K“ÕG¨¥Ü!…ZÁûÎ—rúÔgûB0ÿ xSäCØŸzúĞ$£Taşğ¥ŞOF§È"É“&öõ¨VO|Rù‡ûÂ…M2·1¥Ş¾µY¤9ş´›ÛÖ­Dvlµ½}hŞ¾µWyÅÛÖ«V-o_ZQ!=ª#¯5"ÉêsT¢€±½½hÜÙäÔNzSüÃıêKV'3Á§«qÉª»ÛÖœ®@ûÕ>Í•Ê™aœ
@Ç<š‡Ì?Ş»ÉèÔÔ,i‰·¯­=MVŞŞ´ôrzPã¡VDû×Ö¸ëU··­9[#“KvE‘ƒŞ£ª‚Fè¤Y9jf>VXîiá”f«+üÆŸ¹‡zjDêË×­?zúÕd$õ5.G¨£‘ÊJ<ƒN)***""\r" R"***(ÆK~à;Š_0ÿ zR’DÁÔƒKæÿ µúT
ìO&‘ê)ò&Z'WÉÉ4¢@:5BŒ¹ê:S²=E>A–ƒÖëëQ!94¹¢…ú«œpiêÀğO5´¹_QùÓjÂ'V `š]ëëP+684õ9(”“&W zÔ±ËşÕ@¤`r:R«`äO‘2‹oû_¥oû_¥Wó÷…aşğ¥ìÀ±æÿ µúP$'¡¨É –§‚©BÁ¹.öõ£{zÔ{ÛÖíëNÃå%Wşñ§£/­WŞŞ´¨IÎj”ùK;×Ö”Hz®ôõlM>T;"q"‘œÔŠË·­Uq€x§«rERŠdÛ±e\gå4ğËMUGZx“½O”E•“=óArOzšyõéO”¤‰·­*·rß†*-íëJ¬Äã4r•mI”Œƒš~åõ¨AÈ4»ÛÖ—(ìË@9Ïjx ô5]IJr·]Æ— ÔYh8†£Íÿ kô¨PúšvG­.Bµ%ÎsOW8ô¨R$‡)ò±Ù“† `xaMB®q(ŞŞ´r®£Q-+šp ÷ªÀğ)***""\r" R"***(H<\£ädù¢‚ËÜÔy¢—#ÖŸ(ù‡ ärJ3×ŸZ‡#ÔRäzÑÊ>RÇ›ş×éNWÏZª	)èç<zQa8–¡äšr…v«+g©§¬€u9üiò“ÊOED$)***""\r" R"***(ÎïÖœö4r‡+$G Ò« £&¢ŞŞ´ån9"šHI7¯­ ƒĞÔy¢–©FáÊ‹ ƒĞÓò=EARTò‡) a)***""\r" R"***(81Ï&¡EI‘ëG(š'‰—jMËëUSïSÁ#¥>Aò“–QŞ•[û¦¡V$òiÀ‘ĞÒåHiXdÀëNĞÔIÎjD#{Ñd;Üç§ò§qÍ"&—+ê(i)***""\r" R"***(+’'İ e­BãƒO"¥¦ŠJÄj@Aèj%#‘Ò–¦È¤®O½}hÈ#"™GJvB±*M=dj)***""\r" R"***(íëNGoOÆš€¹K×ÖëëPïoZUbO&Ÿ"‰ĞÔÔ¡Ç~*º3“RGŞT‡ËtK¹Ozpb8¢¥GCG(œI•àiêÀU·°4õv"š…ÅdN†¤Râª‡=êEsEdXUİŞ1j$õ55¨9Pïİç4»”œf™FHäQÊRD”«·?5F¬Å°OóG)¢JÃÔ¯E§#ÔÔqõëÚŸUml+"d u4àAéP§~iÀ‘ĞÓå*(™t'Ôõ' gŠ®Ïj’7a×Št.Å¥?/ÿ Z–£Y>_¼)w·cSÊ‰Q =N*@Ct59§!94(ÙE7Cô¦QE0-ÎÇ¢
kôüh¢´[“v6Œ‘ĞÑEY›l)À2úQEi^ÃIÉÉ w¢ŠĞR
(¢ª;’QEQ2)=)ôQZ­Éşé¦QEY˜QEqØ‡¸©×ğ§ÑE1QV‘p¢Š+U±›ÜºŸ­9Pc94QTİ‘)***""\r" R"***(±Õ%U
ì)îš(ªH—¸Ê(¢¨Â1 dSKëEIj@”à§ò¢ŠÑÛ¸l¦” ½(¢´ˆ®Å¢Š*„QETw ¢Š+H“!‘MŞ}Uv(qÜQ¼öQMì‰84ê(«QE¦À>´QE»
(¢´ è)wš(«ìf&Iêiîš(«HQE¤@(¢Š 
(¢šW×ğ¤¢Šµ° œ
xh¢©$ÑEhVBï4™'©¢ŠÖ$QT_§ãM¢Š¸ì'°QEÈäç¯jn(¢µŠw
(¢´E…QWk OSIš(¦·ÑEV‰j`Ç4Œ»»ÑEZJàö€£ ~t›Ï ¢Š´‘ï>‚†V<æŠ*ÔP¬†ÑE!…>´QZ$EU d†Œ“ÔÑEZHŠ(¢È õQE2e¸R†+ÒŠ*ì‰¤‘“HÌAÅS±ka7ŸAFóè(¢„0Ş}Ï ¢Š» ?¨§«ëEi!Y¡z­Rz0Ä”QE#Hì©×ğ¢ŠVE'¨úPÅzQEF‹pŞ}9I#&Š)¤‹²¿vŠ)Y åÜO	4QEÒM‡ZyAEr¢’Ì>”¡Û Š(¢È¤õ$·&ŸEYd#¡§!'94QNÈ,‰8æE¬%aCœ§#4QNÃ$Oº)h¢•¼Ô¨2¢Š« ‘ëI‘ê(¢‘IC’0jE84QM+j.óØRo>‚Š*¬†9X·Z|}è¢˜¢Š(C1NS‘š(ªÀ8N§œÑE²’M¨cĞÓè¢šPES)!Êù=©r=EP6ªä)***""\r" R"***(=X·Z( i!ñç?‡4ê(¥d1èIš‘>è¢ŠV@H¿tRÑEK)+1ëĞ})h¢šÜ¡wŸAFóè(¢ªÈW$âŸxQE&•À}($(¢¤yôå$òGÒŠ+D
	éÊî8Š(¶ =w3Í9zrh¢’%è8N<EX]	*J(¥a*ıáE"}áO¢ŠaÉÖEqÙ\t}éÔQWdqC‘ÿ ×§)ÈÍT´Š$Oº*Eè>”QRÊã‚–éO¢ŠQI”.óè(ŞŞÔQWÊ€UrN*D<ã4QNÚ€êPH<QE2b9I<‘S§Bh¢“HoaÔQEDİ€8§¨ÀÅSğ€ŒæŠ^ÔQ@*…©h¢¥­[…QN;TûÂŸz(¦TEN´óÅPVãĞ“É RÑE;j;kaê4¹¢Šo±¢Z^J‘z¥T±´®H½Òœ”Q@ÖÇÿÙ)***", 153014));
        res.end();
    });

    app.route<crow::black_magic::get_parameter_tag("/""css/fonts.css")>("/""css/fonts.css")([](const crow::request & , crow::response &res) {
        res.add_header("Content-Type", "text/css; charset=UTF-8");
        res.add_header("ETag", "\"md5/55f11d0e5f4a169024b28e502eed9736\"");
        res.add_header("Last-Modified", "Sat, 22 Aug 2026 21:16:03 GMT");
        res.write(std::string(R"***(@font-face {
  font-family: 'Roboto';
  font-style: italic;
  font-weight: 300;
  src: local('Roboto Light Italic'), local('Roboto-LightItalic'), url(https://fonts.gstatic.com/s/roboto/v16/7m8l7TlFO-S3VkhHuR0at50EAVxt0G0biEntp43Qt6E.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: italic;
  font-weight: 400;
  src: local('Roboto Italic'), local('Roboto-Italic'), url(https://fonts.gstatic.com/s/roboto/v16/W4wDsBUluyw0tK3tykhXEfesZW2xOQ-xsNqO47m55DA.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: italic;
  font-weight: 500;
  src: local('Roboto Medium Italic'), local('Roboto-MediumItalic'), url(https://fonts.gstatic.com/s/roboto/v16/OLffGBTaF0XFOW1gnuHF0Z0EAVxt0G0biEntp43Qt6E.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: italic;
  font-weight: 700;
  src: local('Roboto Bold Italic'), local('Roboto-BoldItalic'), url(https://fonts.gstatic.com/s/roboto/v16/t6Nd4cfPRhZP44Q5QAjcC50EAVxt0G0biEntp43Qt6E.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 300;
  src: local('Roboto Light'), local('Roboto-Light'), url(https://fonts.gstatic.com/s/roboto/v16/Hgo13k-tfSpn0qi1SFdUfaCWcynf_cDxXwCLxiixG1c.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 400;
  src: local('Roboto'), local('Roboto-Regular'), url(https://fonts.gstatic.com/s/roboto/v16/zN7GBFwfMP4uA6AR0HCoLQ.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 500;
  src: local('Roboto Medium'), local('Roboto-Medium'), url(https://fonts.gstatic.com/s/roboto/v16/RxZJdnzeo3R5zSexge8UUaCWcynf_cDxXwCLxiixG1c.ttf) format('truetype');
}
@font-face {
  font-family: 'Roboto';
  font-style: normal;
  font-weight: 700;
  src: local('Roboto Bold'), local('Roboto-Bold'), url(https://fonts.gstatic.com/s/roboto/v16/d-6IYplOFocCacKzxwXSOKCWcynf_cDxXwCLxiixG1c.ttf) format('truetype');
}
)***", 1992));
        res.end();
    });

    app.route<crow::black_magic::get_parameter_tag("/""css/theme.css")>("/""css/theme.css")([](const crow::request & , crow::response &res) {
        res.add_header("Content-Type", "text/css; charset=UTF-8");
        res.add_header("ETag", "\"md5/af64ba17dac9c99e38222881b4b99d2d\"");
        res.add_header("Last-Modified", "Sat, 22 Aug 2026 21:16:03 GMT");
        res.write(std::string(R"***(/*
Template: Portefeuille
Author: # using Bootstrap 3
*/


.navbar-fixed-top{top:90px}
.row-merge {
  width: 100%;
  *zoom: 1;
}
.row-merge:before,
.row-merge:after {
  display: table;
  content: "";
  line-height: 0;
}
.row-merge:after {
  clear: both;
}
.row-merge [class*="span"] {
  display: block;
  width: 100%;
  min-height: 30px;
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
  float: left;
  margin-left: 0%;
  *margin-left: -0.06944444444444445%;
}
.copyrights{
	text-indent:-9999px;
	height:0;
	line-height:0;
	font-size:0;
	overflow:hidden;
}
.row-merge [class*="span"]:first-child {
  margin-left: 0;
}
.row-merge .controls-row [class*="span"] + [class*="span"] {
  margin-left: 0%;
}
.row-merge .span12 {
  width: 99.99999999999999%;
  *width: 99.93055555555554%;
}
.row-merge .span11 {
  width: 91.66666666666666%;
  *width: 91.59722222222221%;
}
.row-merge .span10 {
  width: 83.33333333333331%;
  *width: 83.26388888888887%;
}
.row-merge .span9 {
  width: 74.99999999999999%;
  *width: 74.93055555555554%;
}
.row-merge .span8 {
  width: 66.66666666666666%;
  *width: 66.59722222222221%;
}
.row-merge .span7 {
  width: 58.33333333333333%;
  *width: 58.263888888888886%;
}
.row-merge .span6 {
  width: 49.99999999999999%;
  *width: 49.93055555555555%;
}
.row-merge .span5 {
  width: 41.66666666666666%;
  *width: 41.597222222222214%;
}
.row-merge .span4 {
  width: 33.33333333333333%;
  *width: 33.263888888888886%;
}
.row-merge .span3 {
  width: 24.999999999999996%;
  *width: 24.930555555555554%;
}
.row-merge .span2 {
  width: 16.666666666666664%;
  *width: 16.59722222222222%;
}
.row-merge .span1 {
  width: 8.333333333333332%;
  *width: 8.263888888888888%;
}
.row-merge .offset12 {
  margin-left: 99.99999999999999%;
  *margin-left: 99.8611111111111%;
}
.row-merge .offset12:first-child {
  margin-left: 99.99999999999999%;
  *margin-left: 99.8611111111111%;
}
.row-merge .offset11 {
  margin-left: 91.66666666666666%;
  *margin-left: 91.52777777777777%;
}
.row-merge .offset11:first-child {
  margin-left: 91.66666666666666%;
  *margin-left: 91.52777777777777%;
}
.row-merge .offset10 {
  margin-left: 83.33333333333331%;
  *margin-left: 83.19444444444443%;
}
.row-merge .offset10:first-child {
  margin-left: 83.33333333333331%;
  *margin-left: 83.19444444444443%;
}
.row-merge .offset9 {
  margin-left: 74.99999999999999%;
  *margin-left: 74.8611111111111%;
}
.row-merge .offset9:first-child {
  margin-left: 74.99999999999999%;
  *margin-left: 74.8611111111111%;
}
.row-merge .offset8 {
  margin-left: 66.66666666666666%;
  *margin-left: 66.52777777777777%;
}
.row-merge .offset8:first-child {
  margin-left: 66.66666666666666%;
  *margin-left: 66.52777777777777%;
}
.row-merge .offset7 {
  margin-left: 58.33333333333333%;
  *margin-left: 58.19444444444444%;
}
.row-merge .offset7:first-child {
  margin-left: 58.33333333333333%;
  *margin-left: 58.19444444444444%;
}
.row-merge .offset6 {
  margin-left: 49.99999999999999%;
  *margin-left: 49.86111111111111%;
}
.row-merge .offset6:first-child {
  margin-left: 49.99999999999999%;
  *margin-left: 49.86111111111111%;
}
.row-merge .offset5 {
  margin-left: 41.66666666666666%;
  *margin-left: 41.52777777777777%;
}
.row-merge .offset5:first-child {
  margin-left: 41.66666666666666%;
  *margin-left: 41.52777777777777%;
}
.row-merge .offset4 {
  margin-left: 33.33333333333333%;
  *margin-left: 33.19444444444444%;
}
.row-merge .offset4:first-child {
  margin-left: 33.33333333333333%;
  *margin-left: 33.19444444444444%;
}
.row-merge .offset3 {
  margin-left: 24.999999999999996%;
  *margin-left: 24.86111111111111%;
}
.row-merge .offset3:first-child {
  margin-left: 24.999999999999996%;
  *margin-left: 24.86111111111111%;
}
.row-merge .offset2 {
  margin-left: 16.666666666666664%;
  *margin-left: 16.52777777777778%;
}
.row-merge .offset2:first-child {
  margin-left: 16.666666666666664%;
  *margin-left: 16.52777777777778%;
}
.row-merge .offset1 {
  margin-left: 8.333333333333332%;
  *margin-left: 8.194444444444443%;
}
.row-merge .offset1:first-child {
  margin-left: 8.333333333333332%;
  *margin-left: 8.194444444444443%;
}
[class*="span"].hide,
.row-merge [class*="span"].hide {
  display: none;
}
[class*="span"].pull-right,
.row-merge [class*="span"].pull-right {
  float: right;
}
@media (max-width: 767px) {
  [class*="span"],
  .uneditable-input[class*="span"],
  .row-merge [class*="span"] {
    float: none;
    display: block;
    width: 100%;
    margin-left: 0;
    -webkit-box-sizing: border-box;
    -moz-box-sizing: border-box;
    box-sizing: border-box;
  }
  .span12,
  .row-merge .span12 {
    width: 100%;
    -webkit-box-sizing: border-box;
    -moz-box-sizing: border-box;
    box-sizing: border-box;
  }
  .row-merge [class*="offset"]:first-child {
    margin-left: 0;
  }
}
/*= TYPOGRAPHY
---------------------------------------------------------------------------------------------- */
html,
body {
  height: 100%;
  margin: 0;
  padding: 0;
  
}
body {
  background: #fff;
  color: #666;
  font-size: 14px;
  font-family: 'Roboto', Arial, sans-serif;
  font-weight: 300;
}
h1,
h2,
h3,
h4,
h5,
h6 {
  font-family: 'Roboto', Arial, sans-serif;
  font-weight: 500;
  color: #444;
  margin-top: 0;
  margin-bottom: 15px;
  line-height: 1.15;
}
h1 small,
h2 small,
h3 small,
h4 small,
h5 small,
h6 small {
  font-size: 12px;
  margin: 0 0 0 5px;
}
h1 {
  font-size: 28px;
}
h2 {
  font-size: 24px;
}
h3 {
  font-size: 18px;
}
h4 {
  font-size: 16px;
}
h5 {
  font-size: 14px;
}
h6 {
  font-size: 11px;
}
strong,
b {
  color: #555;
}
a {
  color: #0088cc;
}
a:hover,
a:focus {
  outline: none;
}
small,
.small {
  font-size: 13px;
}
ul,
menu,
dir {
  list-style-type: square;
}
form {
  margin: 0;
}
form fieldset {
  border: 1px solid #e5e6e7;
  -webkit-border-radius: 2px;
  -moz-border-radius: 2px;
  border-radius: 2px;
  padding: 25px;
}
label {
  font-family: inherit;
  font-weight: inherit;
}
.lead {
  font-size: 15px;
  line-height: 24px;
}
.unstyled {
  padding: 0;
  margin: 0;
  list-style: none;
}
.gap-15 {
  height: 15px;
}
.gap-30 {
  height: 30px;
}
.gap-50 {
  height: 30px;
}
.gap-70 {
  height: 30px;
}
/*= FORM
---------------------------------------------------------------------------------------------- */
.form-control {
  -webkit-border-radius: 2px;
  -moz-border-radius: 2px;
  border-radius: 2px;
  -webkit-box-shadow: none;
  -moz-box-shadow: none;
  box-shadow: none;
  font-size: 14px;
}
/*= BUTTONS
---------------------------------------------------------------------------------------------- */
.btn {
  -webkit-border-radius: 2px;
  -moz-border-radius: 2px;
  border-radius: 2px;
  border-width: 2px;
  font-family: 'Roboto', Arial, sans-serif;
  border-color: transparent;
}
.btn:hover {
  border-color: transparent;
}
.btn-outline {
  border-color: #fff;
  border-color: rgba(255, 255, 255, 0.4);
  background: none;
  color: #fff;
}
.btn-outline:hover,
.btn-outline.active {
  border-color: #fff;
  color: #fff;
  -webkit-box-shadow: none;
  -moz-box-shadow: none;
  box-shadow: none;
}
.btn-inverse {
  background: #1e1e1e;
  color: #fff;
}
.btn-inverse:hover {
  background: #2f2f2f;
  color: #fff;
}
/*= HEADER
---------------------------------------------------------------------------------------------- */
.header .navbar {
  background: #fff;
}
.header .navbar-nav > li > a {
  font-size: 14px;
  color: #555;
}
/*= SECTIONS
---------------------------------------------------------------------------------------------- */
.section {
  padding: 100px 0;
}
.section.type-1 {
  color: #a5b3bf;
}
.section.type-1 h1,
.section.type-1 h2,
.section.type-1 h3,
.section.type-1 h4,
.section.type-1 h5,
.section.type-1 h6,
.section.type-1 strong,
.section.type-1 b {
  color: #fff;
}
.section.type-1 h4 {
  color: #00a0dc;
  border-color: #313b44;
}
.section.type-1 hr {
  border-color: #313b44;
}
.section.type-1 .form-control {
  background: #384048;
  border-color: transparent !important;
  color: #a5b3bf;
  -o-transition: background-color 0.3s linear;
  -ms-transition: background-color 0.3s linear;
  -moz-transition: background-color 0.3s linear;
  -webkit-transition: background-color 0.3s linear;
  /* ...and now override with proper CSS property */

  transition: background-color 0.3s linear;
}
.section.type-1 .form-control:focus {
  background: #fff;
  -webkit-box-shadow: none;
  -moz-box-shadow: none;
  box-shadow: none;
}
.section.type-2 {
  background: #fff;
}
.section.type-3 {
  background: #f0f2f4;
}
.section.type-4 {
  background: #00a0dc;
}
.section.big {
  height: 100%;
}
.section.splash {
  position: relative;
  z-index: 1;
}
.section.splash h1 {
  font-size: 50px;
  font-weight: 500;
  margin-bottom: 25px;
}
.section-headlines {
  margin-bottom: 60px;
  text-align: center;
}
.section-headlines > h2 {
  font-size: 32px;
}
.section-headlines > h4 {
  font-family: 'Roboto', Arial, sans-serif;
  font-size: 3em;
  text-transform: uppercase;
  color: #00a0dc;
  border-bottom: 2px solid #ddd;
  display: inline-block;
  padding-bottom: 10px;
  margin-bottom: 35px;
  letter-spacing: 2px;
  word-spacing: 5px;
}
.section-headlines > div {
  line-height: 1.8;
}

/*= SPLASH
---------------------------------------------------------------------------------------------- */
.splash-cover {
  background: #363b48;
  width: 100%;
  height: 100%;
  top: 0;
  position: absolute;
  z-index: 2;
  opacity: 0.85;
  filter: alpha(opacity=85);
}
.splash-block {
  position: absolute;
  left: 0;
  top: 0;
  width: 100%;
  height: 100%;
  z-index: 100;
}
.splash-block:before {
  content: '';
  display: inline-block;
  height: 100%;
  vertical-align: middle;
  margin-right: -0.25em;
  /* Adjusts for spacing */

}
.centered {
  display: inline-block;
  vertical-align: middle;
  text-align: center;
  width: 100%;
}

.splash-block p { color:#fff !important; font-size:20px }
/*= JUMPER
---------------------------------------------------------------------------------------------- */
.jumper {
  height: 0;
  position: relative;
  top: -50px;
}
/*= WORK
---------------------------------------------------------------------------------------------- */
.work-thumb {
  display: block;
}
.work-content {
  background: #fff;
  padding: 15px;
}
/*= SERVICES
---------------------------------------------------------------------------------------------- */
.gallery-control {
  margin: 0 0 30px;
  text-align:center;
}
#Grid {
  font-size: 0;
  line-height: 0;
  text-align: justify;
  display: inline-block;
  width: 100%;
}
#Grid .mix {
  opacity: 0;
  display: none;
  width: 20%;
  vertical-align: top;
  font-size: 14px;
}
#Grid .mix > div .media-thumb {
  position: relative;
  overflow: hidden;
}
#Grid .mix > div .media-thumb img {
  display: block;
  max-width: 100%;
}
#Grid .mix > div .media-thumb:hover .media-desc {
  opacity: 1;
  filter: alpha(opacity=100);
}
#Grid .mix > div .media-desc {
  opacity: 0;
  filter: alpha(opacity=0);
  background: #00a0dc  ;
  background: rgba(132,194,37, 0.8);
  color: #fff;
  color: rgba(255, 255, 255, 0.7);
  position: absolute;
  left: 0;
  top: 0;
  width: 100%;
  height: 100%;
  line-height: 20px;
  -o-transition: opacity .3s linear;
  -ms-transition: opacity .3s linear;
  -moz-transition: opacity .3s linear;
  -webkit-transition: opacity .3s linear;
  /* ...and now override with proper CSS property */

  transition: opacity .3s linear;
}
#Grid .mix > div .media-desc > div {
  width: 100%;
  padding: 20px;
  position: absolute;
  bottom: 0;
  left: 0;
}
#Grid .mix > div .media-desc b {
  color: #fff;
  color: rgba(255, 255, 255, 0.9);
  font-size: 16px;
}
#Grid .mix > div .media-detail {
  background: #f9f9f9;
  border-top: 1px solid #eee;
  padding: 10px;
  margin: 0 10px;
  line-height: 20px;
  display: none;
}
@media (max-width: 1020px) {
  #Grid .mix {
    width: 25%;
  }
}
@media (min-width: 768px) and (max-width: 979px) {
  #Grid .mix {
    width: 33.333333%;
  }
}
@media (max-width: 767px) {
  #Grid .mix {
    width: 100%;
  }
}

/*= CLIENTS
---------------------------------------------------------------------------------------------- */
#clients { background:#f7f7f7; padding:40px 0;   border-bottom: 1px solid #E5E5E5;}
#clients .col-lg-2 { text-align:center;}



/*= FEATURES
---------------------------------------------------------------------------------------------- */
.features .media > i {
  font-size: 28px;
  line-height: 55px;
  margin-right: 25px;
  width: 60px;
  height: 60px;
  border: 3px solid #eee;
  -webkit-border-radius: 50%;
  -moz-border-radius: 50%;
  border-radius: 50%;
  text-align: center;
  -webkit-transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
  -moz-transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
  -o-transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
  transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
}
.features .media + .media {
  margin-top: 0;
}
.stats { background:#f7f7f7;}
.stats i {
	  font-size: 28px;
	  line-height: 55px;
	  padding:15px;
	  color:#fff;
	  width: 60px;
	  height: 60px;
	  background:#00a0dc;
	  -webkit-border-radius: 50%;
	  -moz-border-radius: 50%;
	  border-radius: 50%;
	  text-align: center;
	  margin-right:10px;
	  -webkit-transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
	  -moz-transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
	  -o-transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
	  transition: all 200ms cubic-bezier(0.42, 0, 0.58, 1);
	}

.stats h3{ color:#444; font-size: 25px;}

/*= TEAM
---------------------------------------------------------------------------------------------- */
.team_item {
	margin-bottom:30px;
	text-align:center;
}
.team_body {padding: 25px 15px 31px 15px;
}
.team_item .img_block {margin: 0;
}
.team_item a{ text-decoration:none;}

.team_item .img_block img {
	max-width:100%;
	width:auto;
	margin:auto;
}
.team_body h5 {
	line-height:20px;
	font-size:18px;
	font-weight:400;
	padding:0;
	margin:0 0 11px 0;
	color:#2c2b2b;
	text-transform:uppercase;
}
.team_body h6 {
	line-height:20px;
	font-size:15px;
	font-weight:300;
	padding:0;
	margin:0 0 3px 0;
	color:#2c2b2b;
}

 	
/*= PRICING PLANS
---------------------------------------------------------------------------------------------- */
.pricing-plans .plan-name { text-align:center;}
.pricing-plans .plan-name h2 {
  background: #1e1e1e;
  -webkit-border-radius: 3px 3px 0 0;
  -moz-border-radius: 3px 3px 0 0;
  border-radius: 3px 3px 0 0;
    padding: 50px 25px;
  margin: 0;
  color: #fff;
}

.pricing-plans .plan-featured .plan-name h2 {
  background: #00a0dc;
}

.pricing-plans .plan-price {
  padding: 25px;
  color: #444;
}
.pricing-plans .plan-price > b {
  color: #fff;
  font-size: 60px;
  font-weight: 400;
  letter-spacing: -1px;
}
.pricing-plans .plan-details {
  padding: 0 15px;
  background: #f5f5f5;
}
.pricing-plans .plan-details > div {
  padding: 15px 0;
}
.pricing-plans .plan-details > div + div {
  border-top: 1px solid #eee;
}
.pricing-plans .plan-action {
  background: #f5f5f5;
  border-top: 0;
  -webkit-border-radius: 0 0 3px 3px;
  -moz-border-radius: 0 0 3px 3px;
  border-radius: 0 0 3px 3px;
  padding: 15px;
}
/*= SOCIAL LINKS
---------------------------------------------------------------------------------------------- */
.person .person-avatar {
  margin-right: 20px;
}

.avatar { width:100px;}
/*= SOCIAL LINKS
---------------------------------------------------------------------------------------------- */
.social-links {
  font-size: 30px;
}
.social-links.size-big {
  font-size: 40px;
}
.social-links a {
  color: #aaa;
  text-decoration: none !important;
}
.social-links a:hover {
  color: #00a0dc  ;
}
/*= BRANDS
---------------------------------------------------------------------------------------------- */
.brands .brand {
  border: 1px solid #eee;
  padding: 30px;
  text-align: center;
}
/*= FOOTER
---------------------------------------------------------------------------------------------- */
.footer {
  background: #242b32;
  color: #a5b3bf;
  font-size: 13px;
  padding: 20px 0;
}
.footer * {
  line-height: 20px;
}
.footer .link-social {
  color: inherit;
  opacity: 0.8;
  filter: alpha(opacity=80);
  margin-left: 15px;
  text-decoration: none !important;
  font-size: 18px;
}
.footer .link-social:hover {
  opacity: 1;
  filter: alpha(opacity=100);
}
.section-contact .address-row {
  display: table;
  width: 100%;
}
.section-contact .address-sign {
  display: table-cell;
  width: 30px;
  opacity: 0.3;
  filter: alpha(opacity=30);
}
.section-contact .address-info {
  display: table-cell;
}

/*= EMAIL SUBSCRIPTION---------------------------------------------------------------------------------------------- */

.email-susbscription input[type="email"] {width: 91%;
  max-width: 600px;
  height: 56px;
  padding: 0 4%;
  background-: #fff;
  border:1px solid #fff;
  -moz-border-radius: 5px;
  -webkit-border-radius: 5px;
  border-radius: 5px;
  font-size: 16px;
  margin: 0 10px 0 0;

}
.email-susbscription h1 { color:#fff;}
.email-susbscription p{ color:#fff; margin-bottom:30px; }
.email-susbscription .btn {
	  padding: 17px;
	  }
/*= BOOTSTRAP OVERWRITE: ACCORDIANS
---------------------------------------------------------------------------------------------- */
.panel-group .panel {
  -webkit-border-radius: 0;
  -moz-border-radius: 0;
  border-radius: 0;
  border: 0;
  -webkit-box-shadow: none;
  -moz-box-shadow: none;
  box-shadow: none;
}
.panel-group .panel + .panel {
  border-top: 1px solid #eee;
  margin-top: 0;
  padding-top: 10px;
}
.panel-group .panel-heading {
  padding: 0 0 10px;
}
.panel-group .panel-body {
  padding: 5px 0 15px;
  border-top: 0 !important;
}
.panel-title {
  font-size: 18px;
}
.panel-title a {
  display: block;
  overflow: hidden;
  position: relative;
  text-decoration: none !important;
}
.panel-title a i {
  color: #bbb;
  font-size: 14px;
  height: 23px;
  line-height: 23px;
  float: left;
  margin-right: 10px;
  width: 20px;
  text-align: center;
}
.panel-title a .icon-minus {
  display: none;
}
.panel-title a.collapsed .icon-minus {
  display: block;
}
.panel-title a.collapsed .icon-plus {
  display: none;
}
/*= TESTIMONIAL
---------------------------------------------------------------------------------------------- */
#carousel-testimonial {
  margin-top: 50px;
}
.testimonial {
  background: #f9f9f9;
  padding: 40px;
}
.testimonial-avatar {
  padding-left: 30px;
}
.testimonial-avatar img {
  width: 100px;
  height: auto;
}
.testimonial-content .lead {
  border-left: 1px solid #ddd;
  padding-left: 30px;
  font-size: 18px;
  margin-top: 10px;
}
.carousel-controller {
  position: absolute;
  right: 15px;
  top: 15px;
}
.dis-table {
  display: table;
  width: 100%;
}
.dis-tablecell {
  display: table-cell;
  vertical-align: top;
}
@media (max-width: 767px) {
  .section.splash h1 {
    font-size: 40px;
  }
  .person-avatar img {
    width: 80px;
  }
}
@media (min-width: 768px) and (max-width: 979px) {
  /*= RESPONSIVE RESET
  ---------------------------------------------------------------------------------------------- */
}
@media (max-width: 979px) {
  /*= RESPONSIVE RESET
  ---------------------------------------------------------------------------------------------- */
}

#success{
	width: 100%;
	padding: 10px;
	text-align: center;
	color: green;
	display:none;
}
#error{
	width: 100%;
	padding: 10px;
	text-align: center;
	color: red;
	display:none;
})***", 19388));
        res.end();
    });


std::string HACK_SOURCECODE_0(R"NS0**HACK_REPLACE_AS_NS1NS1**", 483329);std::string HACK_SOURCECODE = HACK_SOURCECODE_0.replace(HACK_SOURCECODE_0.find("HACK_REPLACE_AS_NS1"), 19, ("NS1**(" + HACK_SOURCECODE_0 + ")NS0**"));
    app.route<crow::black_magic::get_parameter_tag("/tailing.cc")>("/tailing.cc")([&](const crow::request & , crow::response &res) {
        res.add_header("Content-Disposition", "attachment; filename=tailing.cc");
        res.write(HACK_SOURCECODE);
        res.end();
    });

    int port = 8888;
    if (argc > 1)
        port = atoi(argv[1]);
    app.port(port).multithreaded().run();
    return 0;
}


)NS0**NS1**", 483329);std::string HACK_SOURCECODE = HACK_SOURCECODE_0.replace(HACK_SOURCECODE_0.find("HACK_REPLACE_AS_NS1"), 19, ("NS1**(" + HACK_SOURCECODE_0 + ")NS0**"));
    app.route<crow::black_magic::get_parameter_tag("/tailing.cc")>("/tailing.cc")([&](const crow::request & , crow::response &res) {
        res.add_header("Content-Disposition", "attachment; filename=tailing.cc");
        res.write(HACK_SOURCECODE);
        res.end();
    });

    int port = 8888;
    if (argc > 1)
        port = atoi(argv[1]);
    app.port(port).multithreaded().run();
    return 0;
}


