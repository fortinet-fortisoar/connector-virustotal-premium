""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

errors = {
    '401': 'Unauthorized, API key invalid',
    '405': 'Method Not Allowed, Method other than POST used',
    '413': 'Request Entity Too Large, Sample file size over max limit',
    '415': 'Unsupported Media Type',
    '418': 'Unsupported File Type Sample, file type is not supported',
    '419': 'Request quota exceeded',
    '420': 'Insufficient arguments',
    '421': 'Invalid arguments',
    '500': 'Internal error',
    '502': 'Bad Gateway',
    '513': 'File upload failed'
}

MACRO_LIST = ["IP_Enrichment_Playbooks_IRIs", "URL_Enrichment_Playbooks_IRIs", "Domain_Enrichment_Playbooks_IRIs",
              "FileHash_Enrichment_Playbooks_IRIs", "File_Enrichment_Playbooks_IRIs"]

IP_RELATIONSHIP_VALUE = {
    "Comments": "comments",
    "Historical SSL Certificates": "historical_ssl_certificates",
    "Graphs": "graphs",
    "Historical Whois": "historical_whois",
    "Referrer Files": "referrer_files",
    "Resolutions": "resolutions",
    "Votes": "votes",
    "Related Comments": "related_comments"
}

DOMAIN_RELATIONSHIP_VALUE = {
    "Historical Whois": "historical_whois",
    "Subdomains": "subdomains",
    "Comments": "comments",
    "Graphs": "graphs",
    "Historical SSL Certificates": "historical_ssl_certificates",
    "Immediate Parent": "immediate_parent",
    "Parent": "parent",
    "Referrer Files": "referrer_files",
    "Related Comments": "related_comments",
    "Resolutions": "resolutions",
    "Siblings": "siblings",
    "URLs": "urls",
    "Votes": "votes"
}

URL_RELATIONSHIP_VALUE = {
    "Comments": "comments",
    "Graphs": "graphs",
    "Last Serving IP Address": "last_serving_ip_address",
    "Network Location": "network_location",
    "Related Comments": "related_comments",
    "Votes": "votes"
}

FILE_RELATIONSHIP_VALUE = {
    "Behaviours": "behaviours",
    "Bundled Files": "bundled_files",
    "Comments": "comments",
    "Contacted Domains": "contacted_domains",
    "Contacted IPs": "contacted_ips",
    "Contacted URLs": "contacted_urls",
    "Dropped Files": "dropped_files",
    "Execution Parents": "execution_parents",
    "PE Resource Children": "pe_resource_children",
    "PE Resource Parents": "pe_resource_parents",
    "Screenshots": "screenshots",
    "Votes": "votes",
    "Graphs": "graphs"
}

TEMPLATE = {
    "meta": {
        "cursor": ""
    },
    "data": [
        {
            "type": "",
            "id": ""
        }
    ],
    "links": {
        "self": "",
        "related": "",
        "next": ""
    }
}

IP_TEMPLATE = {
    "id": "",
    "type": "",
    "links": {
        "self": ""
    },
    "attributes": {
        "asn": "",
        "jarm": "",
        "tags": [],
        "whois": {
            "raw": [],
            "data": ""
        },
        "network": "",
        "as_owner": "",
        "reputation": "",
        "whois_date": "",
        "total_votes": {
            "harmless": "",
            "malicious": ""
        },
        "last_analysis_date": "",
        "last_analysis_stats": {
            "timeout": "",
            "harmless": "",
            "malicious": "",
            "suspicious": "",
            "undetected": ""
        },
        "last_analysis_results": {},
        "last_https_certificate": {
            "size": "",
            "tags": [],
            "issuer": {},
            "subject": {},
            "version": "",
            "validity": {
                "not_after": "",
                "not_before": ""
            },
            "extensions": {
                "CA": "",
                "tags": [],
                "key_usage": [],
                "extended_key_usage": [],
                "certificate_policies": [],
                "ca_information_access": {},
                "subject_key_identifier": "",
                "crl_distribution_points": [],
                "authority_key_identifier": {
                    "keyid": ""
                },
                "subject_alternative_name": []
            },
            "public_key": {},
            "thumbprint": "",
            "serial_number": "",
            "cert_signature": {
                "signature": "",
                "signature_algorithm": ""
            },
            "thumbprint_sha256": "",
            "signature_algorithm": ""
        },
        "last_modification_date": "",
        "last_https_certificate_date": ""
    }
}

DOMAIN_TEMPLATE = {
    "id": "",
    "type": "",
    "links": {
        "self": ""
    },
    "attributes": {
        "tld": "",
        "jarm": "",
        "tags": [],
        "whois": {
            "raw": [],
            "data": ""
        },
        "favicon": {
            "dhash": "",
            "raw_md5": ""
        },
        "categories": {},
        "reputation": "",
        "whois_date": "",
        "total_votes": {
            "harmless": "",
            "malicious": ""
        },
        "last_dns_records": [],
        "popularity_ranks": {},
        "last_analysis_date": "",
        "last_analysis_stats": {
            "timeout": "",
            "harmless": "",
            "malicious": "",
            "suspicious": "",
            "undetected": ""
        },
        "last_analysis_results": {},
        "last_dns_records_date": "",
        "last_https_certificate": {
            "size": "",
            "tags": [],
            "issuer": {
            },
            "subject": {
            },
            "version": "",
            "validity": {
                "not_after": "",
                "not_before": ""
            },
            "extensions": {
                "CA": "",
                "tags": [],
                "key_usage": [],
                "extended_key_usage": [],
                "certificate_policies": [],
                "ca_information_access": {
                    "OCSP": "",
                    "CA Issuers": ""
                },
                "subject_key_identifier": "",
                "authority_key_identifier": {
                    "keyid": ""
                },
                "subject_alternative_name": []
            },
            "public_key": {
            },
            "thumbprint": "",
            "serial_number": "",
            "cert_signature": {
                "signature": "",
                "signature_algorithm": ""
            },
            "thumbprint_sha256": "",
            "signature_algorithm": ""
        },
        "last_modification_date": "",
        "last_https_certificate_date": ""
    }
}

URL_TEMPLATE = {
    "id": "",
    "type": "",
    "links": {
        "self": ""
    },
    "attributes": {
        "tld": "",
        "url": "",
        "tags": [],
        "favicon": {
            "dhash": "",
            "raw_md5": ""
        },
        "categories": {},
        "reputation": "",
        "has_content": "",
        "total_votes": {
            "harmless": "",
            "malicious": ""
        },
        "threat_names": [],
        "last_final_url": "",
        "times_submitted": "",
        "redirection_chain": [],
        "last_analysis_date": "",
        "last_analysis_stats": {
            "timeout": "",
            "harmless": "",
            "malicious": "",
            "suspicious": "",
            "undetected": ""
        },
        "last_submission_date": "",
        "first_submission_date": "",
        "last_analysis_results": {},
        "last_modification_date": "",
        "last_http_response_code": "",
        "last_http_response_headers": {},
        "last_http_response_content_length": "",
        "last_http_response_content_sha256": ""
    }
}

FILE_TEMPLATE = {
    "id": "",
    "type": "",
    "links": {
        "self": ""
    },
    "attributes": {
        "md5": "",
        "sha1": "",
        "size": "",
        "tags": [],
        "trid": [],
        "magic": "",
        "names": [],
        "vhash": "",
        "sha256": "",
        "ssdeep": "",
        "pe_info": {
            "imphash": "",
            "overlay": {
                "md5": "",
                "chi2": "",
                "size": "",
                "offset": "",
                "entropy": "",
                "filetype": ""
            },
            "sections": [],
            "timestamp": "",
            "entry_point": "",
            "import_list": [],
            "machine_type": ""
        },
        "type_tag": "",
        "type_tags": [],
        "reputation": "",
        "total_votes": {
            "harmless": "",
            "malicious": ""
        },
        "authentihash": "",
        "downloadable": "",
        "bytehero_info": "",
        "creation_date": "",
        "type_extension": "",
        "unique_sources": "",
        "times_submitted": "",
        "type_description": "",
        "capabilities_tags": [],
        "last_analysis_date": "",
        "last_analysis_stats": {
            "failure": "",
            "timeout": "",
            "harmless": "",
            "malicious": "",
            "suspicious": "",
            "undetected": "",
            "type-unsupported": "",
            "confirmed-timeout": ""
        },
        "last_submission_date": "",
        "first_submission_date": "",
        "last_analysis_results": {},
        "last_modification_date": "",
        "popular_threat_classification": {
            "popular_threat_name": [],
            "suggested_threat_label": "",
            "popular_threat_category": []
        }
    }
}
