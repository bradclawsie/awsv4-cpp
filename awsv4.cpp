#include "awsv4.hpp"

namespace AWSV4 {

    // http://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c
    void sha256(const std::string str, unsigned char outputBuffer[SHA256_DIGEST_LENGTH]) {
        char *c_string = new char [str.length()+1];
        std::strcpy(c_string, str.c_str());        
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, c_string, strlen(c_string));
        SHA256_Final(hash, &sha256);
        for (int i=0;i<SHA256_DIGEST_LENGTH;i++) {
            outputBuffer[i] = hash[i];
        }
    }
    
    const std::string sha256_base16(const std::string str) { 
        unsigned char hashOut[SHA256_DIGEST_LENGTH];
        AWSV4::sha256(str,hashOut);
        char outputBuffer[65];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(outputBuffer + (i * 2), "%02x", hashOut[i]);
        }
        outputBuffer[64] = 0;
        return std::string{outputBuffer};
    }

    // -----------------------------------------------------------------------------------
    // TASK 1 - create a canonical request
    // http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    // uri should be normalize()'d before calling here, as this takes a const ref param and we don't 
    // want to normalize repeatedly. the return value is not a uri specifically, but a uri fragment,
    // as such the return value should not be used to initialize a uri object
    const std::string canonicalize_uri(const Poco::URI& uri) {
        const auto p = uri.getPath();
        if (p.empty()) return "/";
        std::string encoded_path;
        Poco::URI::encode(uri.getPath(),"",encoded_path);
        return encoded_path;
    }

    const std::string canonicalize_query(const Poco::URI& uri) {
        const std::string query_delim{"&"};
        const auto q = uri.getQuery();
        if (q.empty()) return "";
        const Poco::StringTokenizer tok{q,query_delim,0};
        std::vector<std::string> parts; 
        for (const auto t:tok) {
            std::string encoded_arg;
            Poco::URI::encode(t,"",encoded_arg);
            parts.push_back(encoded_arg);
        }
        std::sort(parts.begin(),parts.end());
        return boost::algorithm::join(parts,query_delim);
    }

    // create a map of the "canonicalized" headers
    const std::map<std::string,std::string> canonicalize_headers(const std::vector<std::string>& headers) {
        const std::string header_delim{":"};
        std::map<std::string,std::string> header_key2val;
        for (const auto h:headers) {
            const Poco::StringTokenizer pair{h,header_delim,2}; // 2 -> TOK_TRIM, trim whitespace
            if (pair.count() != 2) throw std::invalid_argument("malformed header:" + h);
            std::string key{pair[0]};
            const std::string val{pair[1]};
            if (key.empty() || val.empty()) throw std::invalid_argument("malformed header:" + h);
            boost::algorithm::to_lower(key);
            header_key2val[key] = val;
        }
        return header_key2val;
    }

    // get a string representation of header:value lines
    const std::string map_headers_string(const std::map<std::string,std::string>& header_key2val) {
        const std::string pair_delim{":"};
        std::string h;
        for (auto& kv:header_key2val) {
            h.append(kv.first + pair_delim + kv.second + ENDL);
        }
        return h;
    }

    // get a string representation of the header names
    const std::string map_signed_headers(const std::map<std::string,std::string>& header_key2val) {
        const std::string signed_headers_delim{";"};
        std::vector<std::string> ks;
        for (auto& kv:header_key2val) {
            ks.push_back(kv.first);
        }
        return boost::algorithm::join(ks,signed_headers_delim);
    }

    const std::string canonicalize_request(const std::string& http_request_method,
                                           const std::string& canonical_uri,
                                           const std::string& canonical_query_string,
                                           const std::string& canonical_headers,
                                           const std::string& signed_headers,
                                           const std::string& payload) {
        return http_request_method + ENDL + 
            canonical_uri + ENDL +
            canonical_query_string + ENDL + 
            canonical_headers + ENDL + 
            signed_headers + ENDL +
            sha256_base16(payload);
    }

    // -----------------------------------------------------------------------------------
    // TASK 2 - create a string-to-sign
    // http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html

    const std::string string_to_sign(const std::string& algorithm,
                                     const std::time_t& request_date,
                                     const std::string& credential_scope,
                                     const std::string& hashed_canonical_request) {
        return algorithm + ENDL + 
            ISO8601_date(request_date) + ENDL +
            credential_scope + ENDL + 
            hashed_canonical_request;
    }

    const std::string credential_scope(const std::time_t& request_date, 
                                       const std::string region,
                                       const std::string service) {
        const std::string s{"/"};
        return utc_yyyymmdd(request_date) + s + region + s + service + s + AWS4_REQUEST; 
    }

    // time_t -> 20131222T043039Z
    const std::string ISO8601_date(const std::time_t& t) {
        char buf[sizeof "20111008T070709Z"];
        std::strftime(buf, sizeof buf, "%Y%m%dT%H%M%SZ", std::gmtime(&t));
        std::string formatted{buf};
        return formatted;
    }

    // time_t -> 20131222
    const std::string utc_yyyymmdd(const std::time_t& t) {
        char buf[sizeof "20111008"];
        std::strftime(buf, sizeof buf, "%Y%m%d", std::gmtime(&t));
        std::string formatted{buf};
        return formatted;
    }
    
    // -----------------------------------------------------------------------------------
    // TASK 3
    // http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

    const std::string calculate_signature(const std::time_t& request_date, 
                                          const std::string secret,
                                          const std::string region,
                                          const std::string service,
                                          const std::string string_to_sign) {

        const std::string k1{AWS4 + secret};
        char *c_k1 = new char [k1.length()+1];
        std::strcpy(c_k1, k1.c_str());

        auto yyyymmdd = utc_yyyymmdd(request_date);
        char *c_yyyymmdd = new char [yyyymmdd.length()+1];
        std::strcpy(c_yyyymmdd, yyyymmdd.c_str());

        unsigned char* kDate;
        kDate = HMAC(EVP_sha256(), c_k1, strlen(c_k1), 
                     (unsigned char*)c_yyyymmdd, strlen(c_yyyymmdd), NULL, NULL); 

        char *c_region = new char [region.length()+1];
        std::strcpy(c_region, region.c_str());        
        unsigned char *kRegion;
        kRegion = HMAC(EVP_sha256(), kDate, strlen((char *)kDate), 
                     (unsigned char*)c_region, strlen(c_region), NULL, NULL); 

        char *c_service = new char [service.length()+1];
        std::strcpy(c_service, service.c_str());        
        unsigned char *kService;
        kService = HMAC(EVP_sha256(), kRegion, strlen((char *)kRegion), 
                     (unsigned char*)c_service, strlen(c_service), NULL, NULL); 

        char *c_aws4_request = new char [AWS4_REQUEST.length()+1];
        std::strcpy(c_aws4_request, AWS4_REQUEST.c_str());        
        unsigned char *kSigning;
        kSigning = HMAC(EVP_sha256(), kService, strlen((char *)kService), 
                     (unsigned char*)c_aws4_request, strlen(c_aws4_request), NULL, NULL); 

        char *c_string_to_sign = new char [string_to_sign.length()+1];
        std::strcpy(c_string_to_sign, string_to_sign.c_str());        
        unsigned char *kSig;
        kSig = HMAC(EVP_sha256(), kSigning, strlen((char *)kSigning), 
                     (unsigned char*)c_string_to_sign, strlen(c_string_to_sign), NULL, NULL); 

        char outputBuffer[65];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(outputBuffer + (i * 2), "%02x", kSig[i]);
        }
        outputBuffer[64] = 0;
        return std::string{outputBuffer};
    }
}
