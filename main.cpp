#include <iostream>
#include "awsv4.hpp"

int main() {

    // 20110909T233600Z
    struct std::tm t;
    t.tm_sec = 0;
    t.tm_min = 36;
    t.tm_hour = 16;
    t.tm_mon = 8;
    t.tm_year = 2011 - 1900;
    t.tm_isdst = -1; 
    t.tm_mday = 9;   
    const std::time_t request_date = std::mktime(&t);

    const std::string region{"us-east-1"};
    const std::string service{"iam"};

    const std::string base_uri{"http://iam.amazonaws.com/"};
    const std::string query_args{""};
    const std::string uri_str{base_uri + "?" + query_args};

    Poco::URI uri;
    try {
        uri = Poco::URI(uri_str);
    } catch (std::exception& e) {
        throw std::runtime_error(e.what());
    }
    uri.normalize();
    const auto canonical_uri = AWSV4::canonicalize_uri(uri);
    
    const auto canonical_query = AWSV4::canonicalize_query(uri);
    const std::vector<std::string> headers{"host: iam.amazonaws.com",
            "Content-type: application/x-www-form-urlencoded; charset=utf-8",
            "x-amz-date: 20110909T233600Z"};
    
    const auto canonical_headers_map = AWSV4::canonicalize_headers(headers);
    const auto headers_string = AWSV4::map_headers_string(canonical_headers_map);
    const auto signed_headers = AWSV4::map_signed_headers(canonical_headers_map);

    const std::string payload{"Action=ListUsers&Version=2010-05-08"};
    auto sha256_payload = AWSV4::sha256_base16(payload); 
    
    const auto canonical_request = AWSV4::canonicalize_request(AWSV4::POST,
                                                               canonical_uri,
                                                               canonical_query,
                                                               headers_string,
                                                               signed_headers,
                                                               payload);
    
    std::cout << "--\n" << canonical_request << "\n--\n" << std::endl;

    auto hashed_canonical_request = AWSV4::sha256_base16(canonical_request); 
    std::cout << hashed_canonical_request << std::endl;

    auto credential_scope = AWSV4::credential_scope(request_date,region,service);

    auto string_to_sign = AWSV4::string_to_sign(AWSV4::STRING_TO_SIGN_ALGO,
                                                request_date,
                                                credential_scope,
                                                hashed_canonical_request);

    std::cout << "--\n" << string_to_sign << "\n----\n" << std::endl;

    const std::string secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    
    auto signature = AWSV4::calculate_signature(request_date, 
                                                secret,
                                                region,
                                                service,
                                                string_to_sign);
    
    std::cout << signature << std::endl;

    return 0;
}
