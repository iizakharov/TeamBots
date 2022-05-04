import re
from time import sleep

import pynetbox
import pyexcel
from datetime import datetime, timedelta
from operator import itemgetter
import csv
from collections import Counter

from elasticsearch import Elasticsearch, NotFoundError

from env import IPAM_URL, IPAM_TOKEN, ELK_USER, ELK_PASS, ELK_URL


def try_repeat(func):
    def wrapper(*args, **kwargs):
        count = 3
        while count:
            try:
                return func(*args, **kwargs)
            except NotFoundError:
                count = 0
                print('Сервер перегружен, попробуйте позже!')
            except Exception as e:
                print(e)
                print('[bold magenta]ReConnect...[/bold magenta]')
                count -= 1
    return wrapper


def connect_elk(quiet=None):
    user = ELK_USER
    pssw = ELK_PASS
    url = ELK_URL

    es = Elasticsearch(
        [url],
        http_auth=(user, pssw),
        scheme='http',
        timeout=20
    )
    if not quiet:
        print('Connecting to ELK...')
    return es


def get_date(sed=None, days=None):
    delta = 24 * int(days) if days else 24
    if sed:
        time_to = datetime.now() + timedelta(hours=3)
        time_at = time_to - timedelta(days=30)
        return time_at.strftime('%Y-%m-%dT%H:%M:00.000Z'), time_to.strftime('%Y-%m-%dT%H:%M:00.000Z')
    time_to = datetime.now()  # + timedelta(hours=3)
    time_at = time_to - timedelta(hours=delta)
    return time_at.strftime('%Y-%m-%dT%H:%M:00.000Z'), time_to.strftime('%Y-%m-%dT%H:%M:00.000Z')


def get_elk_request_body(tenant=None, all_attacks=None, stats=None, events=None, stats_event=None, gu_ad=None, ip=None,
                         sed=None, previlege=None, vpo=None, days=None):

    date_from, date_to = get_date(days=days) if days else get_date()
    if all_attacks:
        body = {
            "aggs": {
                "2": {
                    "terms": {
                        "field": "region.keyword",
                        "order": {
                            "_count": "desc"
                        },
                        "size": 10
                    },
                    "aggs": {
                        "3": {
                            "terms": {
                                "field": "sd.event.p1.keyword",
                                "order": {
                                    "_count": "desc"
                                },
                                "size": 10
                            },
                            "aggs": {
                                "5": {
                                    "terms": {
                                        "field": "mchs_organisation.keyword",
                                        "order": {
                                            "_count": "desc"
                                        },
                                        "size": 10
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "size": 0,
            "stored_fields": [
                "*"
            ],
            "script_fields": {},
            "docvalue_fields": [
                {
                    "field": "@timestamp",
                    "format": "date_time"
                }
            ],
            "_source": {
                "excludes": []
            },
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "match_all": {}
                        },
                        {
                            "exists": {
                                "field": "attack_source_ip"
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": date_from,
                                    "lte": date_to,
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": [
                        {
                            "match_phrase": {
                                "attack_source_ip.keyword": "0.0.0.0"
                            }
                        },
                        {
                            "match_phrase": {
                                "attack_target_ip.keyword": "0.0.0.0"
                            }
                        }
                    ]
                }
            }
        }
        return body
    elif sed:
        date_from, date_to = get_date(sed=True)
        body = {
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc",
                        "unmapped_type": "boolean"
                    }
                }
            ],
            "aggs": {
                "2": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "30m",
                        "time_zone": "Europe/Moscow",
                        "min_doc_count": 1
                    }
                }
            },
            "stored_fields": [
                "*"
            ],
            "docvalue_fields": [
                {
                    "field": "@timestamp",
                    "format": "date_time"
                },
                {
                    "field": "docker.time",
                    "format": "date_time"
                },
                {
                    "field": "event.created",
                    "format": "date_time"
                },
                {
                    "field": "nextcloud.time",
                    "format": "date_time"
                },
                {
                    "field": "nginx.time_iso8601",
                    "format": "date_time"
                },
                {
                    "field": "snoopy.date_iso_8601",
                    "format": "date_time"
                },
                {
                    "field": "winlog.event_data.NewTime",
                    "format": "date_time"
                },
                {
                    "field": "winlog.event_data.PreviousTime",
                    "format": "date_time"
                }
            ],
            "_source": {
                "excludes": []
            },
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "match_all": {}
                        },
                        {
                            "exists": {
                                "field": "user_address"
                            }
                        },
                        {
                            "match_phrase": {
                                "user_address": f"{ip}"
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                     "gte": date_from,
                                    "lte": date_to,
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": [
                        {
                            "match_phrase": {
                                "user_agent": "Drupal Command"
                            }
                        }
                    ]
                }
            }
        }
        return body
    elif gu_ad and tenant:
        print('Body: gu_ad and tenant')
        body = {
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc",
                        "unmapped_type": "boolean"
                    }
                }
            ],
            "aggs": {
                "2": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "30m",
                        "time_zone": "Europe/Moscow",
                        "min_doc_count": 1
                    }
                }
            },
            "stored_fields": [
                "*"
            ],
            "script_fields": {
                "user_logon_only": {
                    "script": {
                        "source": "if (doc.containsKey('winlog.event_data.TargetUserName.keyword') && !doc['winlog.event_data.TargetUserName.keyword'].empty) {\n    if (doc['winlog.event_data.TargetUserName.keyword'].value =~ /^.*\\$$/) {\n        return false;\n    } else {\n        return true;\n    }\n}\nreturn false;",
                        "lang": "painless"
                    }
                },
                "region_url": {
                    "script": {
                        "source": "if (doc.containsKey('region.keyword') && !doc['region.keyword'].empty) {\n    def region_value = doc['region.keyword'].value;    \n    return region_value;\n}\ndef region_value = '#';    \nreturn region_value;",
                        "lang": "painless"
                    }
                }
            },
            "docvalue_fields": [
                {
                    "field": "@timestamp",
                    "format": "date_time"
                },
                {
                    "field": "docker.time",
                    "format": "date_time"
                },
                {
                    "field": "event.created",
                    "format": "date_time"
                },
                {
                    "field": "nextcloud.time",
                    "format": "date_time"
                },
                {
                    "field": "nginx.time_iso8601",
                    "format": "date_time"
                },
                {
                    "field": "snoopy.date_iso_8601",
                    "format": "date_time"
                },
                {
                    "field": "winlog.event_data.NewTime",
                    "format": "date_time"
                },
                {
                    "field": "winlog.event_data.PreviousTime",
                    "format": "date_time"
                }
            ],
            "_source": {
                "excludes": []
            },
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "match_all": {}
                        },
                        {
                            "match_phrase": {
                                "event.code": 4625
                            }
                        },
                        {
                            "match_phrase": {
                                "region": tenant
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": date_from,
                                    "lte": date_to,
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": [
                        {
                            "script": {
                                "script": {
                                    "source": "boolean compare(Supplier s, def v) {return s.get() == v;}compare(() -> { if (doc.containsKey('winlog.event_data.TargetUserName.keyword') && !doc['winlog.event_data.TargetUserName.keyword'].empty) {\n    if (doc['winlog.event_data.TargetUserName.keyword'].value =~ /^.*\\$$/) {\n        return false;\n    } else {\n        return true;\n    }\n}\nreturn false; }, params.value);",
                                    "lang": "painless",
                                    "params": {
                                        "value": False
                                    }
                                }
                            }
                        }
                    ]
                }
            },
        }
    elif events:
        # dates = make_date(all_attacks=True)
        body = {
            "aggs": {
                "2": {
                    "terms": {
                        "script": {
                            "source": "if (doc.containsKey('region.keyword') && !doc['region.keyword'].empty) {\n    def region_value = doc['region.keyword'].value;    \n    return region_value;\n}\ndef region_value = '#';    \nreturn region_value;",
                            "lang": "painless"
                        },
                        "order": {
                            "_key": "desc"
                        },
                        "value_type": "string",
                        "size": 20
                    },
                    "aggs": {
                        "6": {
                            "terms": {
                                "field": "winlog.event_data.TargetUserName.keyword",
                                "order": {
                                    "_key": "desc"
                                },
                                "size": 50
                            },
                            "aggs": {
                                "7": {
                                    "terms": {
                                        "script": {
                                            "source": "if (doc.containsKey('winlog.event_data.IpAddress.keyword') && !doc['winlog.event_data.IpAddress.keyword'].empty) {\n    def ip_value = doc['winlog.event_data.IpAddress.keyword'].value;\n    return ip_value;\n}\ndef region_value = '-';    \nreturn region_value;",
                                            "lang": "painless"
                                        },
                                        "order": {
                                            "_key": "desc"
                                        },
                                        "value_type": "string",
                                        "size": 20
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "size": 0,
            "stored_fields": [
                "*"
            ],
            "_source": {
                "excludes": []
            },
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "match_all": {}
                        },
                        {
                            "match_phrase": {
                                "event.code": "4625"
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": date_from,
                                    "lte": date_to,
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": [
                        {
                            "script": {
                                "script": {
                                    "source": "boolean compare(Supplier s, def v) {return s.get() == v;}compare(() -> { if (doc.containsKey('winlog.event_data.TargetUserName.keyword') && !doc['winlog.event_data.TargetUserName.keyword'].empty) {\n    if (doc['winlog.event_data.TargetUserName.keyword'].value =~ /^.*\\$$/) {\n        return false;\n    } else {\n        return true;\n    }\n}\nreturn false; }, params.value);",
                                    "lang": "painless",
                                    "params": {
                                        "value": False
                                    }
                                }
                            }
                        }
                    ]
                }
            }
        }
        return body
    elif stats_event:
        # dates = make_date(all_attacks=True)
        body_arms = {
            "aggs": {
                "1": {
                    "cardinality": {
                        "field": "region.keyword"
                    }
                },
                "2": {
                    "cardinality": {
                        "field": "winlog.event_data.WorkstationName.keyword"
                    }
                }
            },
            "size": 0,
            "stored_fields": [
                "*"
            ],
            "script_fields": {
                "user_logon_only": {
                    "script": {
                        "source": "if (doc.containsKey('winlog.event_data.TargetUserName.keyword') && !doc['winlog.event_data.TargetUserName.keyword'].empty) {\n    if (doc['winlog.event_data.TargetUserName.keyword'].value =~ /^.*\\$$/) {\n        return true;\n    }\n}\nreturn false;",
                        "lang": "painless"
                    }
                }
            },
            "docvalue_fields": [
                {
                    "field": "@timestamp",
                    "format": "date_time"
                },
                {
                    "field": "docker.time",
                    "format": "date_time"
                },
                {
                    "field": "event.created",
                    "format": "date_time"
                },
                {
                    "field": "nextcloud.time",
                    "format": "date_time"
                },
                {
                    "field": "nginx.time_iso8601",
                    "format": "date_time"
                },
                {
                    "field": "snoopy.date_iso_8601",
                    "format": "date_time"
                },
                {
                    "field": "winlog.event_data.NewTime",
                    "format": "date_time"
                },
                {
                    "field": "winlog.event_data.PreviousTime",
                    "format": "date_time"
                }
            ],
            "_source": {
                "excludes": []
            },
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {
                                        "script": {
                                            "script": {
                                                "source": "boolean compare(Supplier s, def v) {return s.get() == v;}compare(() -> { if (doc.containsKey('winlog.event_data.TargetUserName.keyword') && !doc['winlog.event_data.TargetUserName.keyword'].empty) {\n    if (doc['winlog.event_data.TargetUserName.keyword'].value =~ /^.*\\$$/) {\n        return true;\n    }\n}\nreturn false; }, params.value);",
                                                "lang": "painless",
                                                "params": {
                                                    "value": False
                                                }
                                            }
                                        }
                                    }
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {
                                        "match_phrase": {
                                            "event.code": "4625"
                                        }
                                    }
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        {
                            "match_phrase": {
                                "type": "dc"
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": date_from,
                                    "lte": date_to,
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": []
                }
            }
        }
        body = {
            "aggs": {
                "4": {
                    "terms": {
                        "field": "winlog.event_id",
                        "order": {
                            "_count": "desc"
                        },
                        "size": 6
                    }
                }
            },
            "size": 0,
            "stored_fields": [
                "*"
            ],
            "script_fields": {
                "_user_logon_only": {
                    "script": {
                        "source": "if (doc['winlog.event_data.TargetUserName.keyword'].size() > 0) {\n    def m = /([a-zA-Z0-9-]+)\\$/.matcher(doc['winlog.event_data.TargetUserName.keyword'].value);\n    if ( m.matches() ) {\n        return 1;\n    }\n}\nreturn 0;",
                        "lang": "painless"
                    }
                },
                "user_logon_only": {
                    "script": {
                        "source": "if (doc.containsKey('winlog.event_data.TargetUserName.keyword') && !doc['winlog.event_data.TargetUserName.keyword'].empty) {\n    if (doc['winlog.event_data.TargetUserName.keyword'].value =~ /^.*\\$$/) {\n        return true;\n    }\n}\nreturn false;",
                        "lang": "painless"
                    }
                }
            },
            "docvalue_fields": [
                {
                    "field": "@timestamp",
                    "format": "date_time"
                },
                {
                    "field": "docker.time",
                    "format": "date_time"
                },
                {
                    "field": "event.created",
                    "format": "date_time"
                },
                {
                    "field": "nextcloud.time",
                    "format": "date_time"
                },
                {
                    "field": "nginx.time_iso8601",
                    "format": "date_time"
                },
                {
                    "field": "snoopy.date_iso_8601",
                    "format": "date_time"
                },
                {
                    "field": "winlog.event_data.NewTime",
                    "format": "date_time"
                },
                {
                    "field": "winlog.event_data.PreviousTime",
                    "format": "date_time"
                }
            ],
            "_source": {
                "excludes": []
            },
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {
                                        "script": {
                                            "script": {
                                                "source": "boolean compare(Supplier s, def v) {return s.get() == v;}compare(() -> { if (doc.containsKey('winlog.event_data.TargetUserName.keyword') && !doc['winlog.event_data.TargetUserName.keyword'].empty) {\n    if (doc['winlog.event_data.TargetUserName.keyword'].value =~ /^.*\\$$/) {\n        return true;\n    }\n}\nreturn false; }, params.value);",
                                                "lang": "painless",
                                                "params": {
                                                    "value": False
                                                }
                                            }
                                        }
                                    }
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        {
                            "match_phrase": {
                                "type": "dc"
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {
                                        "match_phrase": {
                                            "winlog.event_id": "4624"
                                        }
                                    },
                                    {
                                        "match_phrase": {
                                            "winlog.event_id": "4625"
                                        }
                                    },
                                    {
                                        "match_phrase": {
                                            "winlog.event_id": "4627"
                                        }
                                    }
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": date_from,
                                    "lte": date_to,
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": []
                }
            }
        }
        return body_arms, body
    elif vpo:
        # dates = make_date(all_attacks=True)
        body = {
            "sort": [
                {
                  "@timestamp": {
                    "order": "desc",
                    "unmapped_type": "boolean"
                  }
                }
              ],
              "aggs": {
                "2": {
                  "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "12h",
                    "time_zone": "Europe/Moscow",
                    "min_doc_count": 1
                  }
                }
              },
              "stored_fields": [
                "*"
              ],
              "_source": {
                "excludes": []
              },
              "query": {
                "bool": {
                  "must": [],
                  "filter": [
                    {
                      "bool": {
                        "should": [],
                        "minimum_should_match": 1
                      }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": date_from,
                                "lte": date_to,
                                "format": "strict_date_optional_time"
                            }
                        }
                    }
                    ],
                    "should": [],
                    "must_not": []
                }
            }
        }
        vpos = open('vpo.txt', 'r').readlines()
        for vpo in vpos:
            vpo = vpo.split('\n')[0]
            body['query']['bool']['filter'][0]['bool']['should'].append({"query_string": {"query": f"*{vpo}*"}})
        if tenant:
            body['query']['bool']['filter'].append({"match_phrase": {"region": tenant}})
        return body
    elif tenant:
        body = {
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc",
                        "unmapped_type": "boolean"
                    }
                }
            ],
            "aggs": {
                "2": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "30m",
                        "time_zone": "Europe/Moscow",
                        "min_doc_count": 1
                    }
                }
            },
            "stored_fields": [
                "*"
            ],
            "script_fields": {
                "region_url": {
                    "script": {
                        "source": "def region_value = doc['region.keyword'].value;",
                        "lang": "painless"
                    }
                }
            },
            "docvalue_fields": [
                {
                    "field": "@timestamp",
                    "format": "date_time"
                }
            ],
            "_source": {
                "excludes": []
            },
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "match_all": {}
                        },
                        {
                            "exists": {
                                "field": "attack_source_ip"
                            }
                        },
                        {
                            "match_phrase": {
                                "region": tenant
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    # "gte": "2021-12-26T09:23:24.501Z",
                                    "gte": date_from,
                                    # "lte": "2021-12-27T09:23:24.501Z",
                                    "lte": date_to,
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": [
                        {
                            "match_phrase": {
                                "attack_source_ip": "0.0.0.0"
                            }
                        },
                        {
                            "match_phrase": {
                                "attack_target_ip": "0.0.0.0"
                            }
                        }
                    ]
                }
            }
        }
        return body
    elif stats:
        body = {
            "aggs": {
                "3": {
                    "cardinality": {
                        "field": "attack_target_ip.keyword"
                    }
                },
                "4": {
                    "cardinality": {
                        "field": "attack_source_ip.keyword"
                    }
                },
                "6": {
                    "cardinality": {
                        "field": "region.keyword"
                    }
                }
            },
            "size": 0,
            "stored_fields": [
                "*"
            ],
            "docvalue_fields": [
                {
                    "field": "@timestamp",
                    "format": "date_time"
                }
            ],
            "_source": {
                "excludes": []
            },
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "match_all": {}
                        },
                        {
                            "exists": {
                                "field": "attack_source_ip"
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": date_from,
                                    "lte": date_to,
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": [
                        {
                            "match_phrase": {
                                "attack_source_ip.keyword": "0.0.0.0"
                            }
                        },
                        {
                            "match_phrase": {
                                "attack_target_ip.keyword": "0.0.0.0"
                            }
                        }
                    ]
                }
            }
        }
        return body
    elif previlege:
        # dates = make_date(all_attacks=True)
        body = {
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc",
                        "unmapped_type": "boolean"
                    }
                }
            ],
            "aggs": {
                "2": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "3h",
                        "time_zone": "Europe/Moscow",
                        "min_doc_count": 1
                    }
                }
            },
            "stored_fields": [
                "*"
            ],
            "_source": {
                "excludes": []
            },
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {
                                        "bool": {
                                            "should": [
                                                {
                                                    "query_string": {
                                                        "fields": [
                                                            "winlog.event_data.TargetUserName"
                                                        ],
                                                        "query": "*admin*"
                                                    }
                                                }
                                            ],
                                            "minimum_should_match": 1
                                        }
                                    },
                                    {
                                        "bool": {
                                            "should": [
                                                {
                                                    "query_string": {
                                                        "fields": [
                                                            "winlog.event_data.TargetUserName"
                                                        ],
                                                        "query": "*админ*"
                                                    }
                                                }
                                            ],
                                            "minimum_should_match": 1
                                        }
                                    }
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        {
                            "match_phrase": {
                                "type": "dc"
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {
                                        "match_phrase": {
                                            "event.code": "4728"
                                        }
                                    },
                                    {
                                        "match_phrase": {
                                            "event.code": "4727"
                                        }
                                    },
                                    {
                                        "match_phrase": {
                                            "event.code": "4729"
                                        }
                                    },
                                    {
                                        "match_phrase": {
                                            "event.code": "4730"
                                        }
                                    }
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": date_from,
                                    "lte": date_to,
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": []
                }
            }
        }
        return body

    else:
        body = {
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc",
                        "unmapped_type": "boolean"
                    }
                }
            ],
            "aggs": {
                "2": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "30m",
                        "time_zone": "Europe/Moscow",
                        "min_doc_count": 1
                    }
                }
            },
            "stored_fields": [
                "*"
            ],
            "script_fields": {
                "region_url": {
                    "script": {
                        "source": "def region_value = doc['region.keyword'].value;",
                        "lang": "painless"
                    }
                }
            },
            "docvalue_fields": [
                {
                    "field": "@timestamp",
                    "format": "date_time"
                }
            ],
            "_source": {
                "excludes": []
            },
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "match_all": {}
                        },
                        {
                            "exists": {
                                "field": "attack_source_ip"
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    # "gte": "2021-12-26T09:23:24.501Z",
                                    "gte": date_from,
                                    # "lte": "2021-12-27T09:23:24.501Z",
                                    "lte": date_to,
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": [
                        {
                            "match_phrase": {
                                "attack_source_ip": "0.0.0.0"
                            }
                        },
                        {
                            "match_phrase": {
                                "attack_target_ip": "0.0.0.0"
                            }
                        }
                    ]
                }
            }
        }
    return body


def connect_ipam():
    print('Connecting to ipsm.mchs.ru')
    nb = pynetbox.api(
        IPAM_URL,
        token=IPAM_TOKEN
    )
    return nb


def get_data_from_ipam(ip, connect=None):  # noqa: C901
    if connect is None:
        nb = connect_ipam()
    else:
        nb = connect
    tenant = None
    region = None
    prefix = None
    aggregate = None
    try:
        q = nb.ipam.ip_addresses.get(address=ip)
    except:
        q = None
    try:
        prefix = nb.ipam.prefixes.get(q=ip)

    except:  # noqa: E722
        prefixes = nb.ipam.prefixes.filter(q=ip)
        for item in prefixes:
            prefix = item
            break
    try:
        aggregate = nb.ipam.aggregates.get(q=prefix.prefix)
    except:  # noqa: E722
        aggregate = nb.ipam.aggregates.get(q=ip)
    try:
        tenant = nb.tenancy.tenants.get(name=q.tenant)
    except:  # noqa: E722
        try:
            tenant_name = None
            for attr in aggregate:
                if tenant_name is not None:
                    break
                if 'tenant' in attr:
                    tenant_name = aggregate.tenant.name
                    break
                else:
                    for attr in prefix:
                        if 'tenant' in attr:
                            tenant_name = prefix.tenant.name
                            break
            tenant = nb.tenancy.tenants.get(name=tenant_name)
        except:  # noqa: E722
            print('Учреждения не закреплено за адресом')
    if tenant:
        for address in nb.dcim.sites.filter(tenant_id=tenant.id):
            addresses = address
            if addresses.region is None:
                continue
            else:
                region = addresses.region
                break
    if q is None:
        res = {
            'ip': ip,
            'region': region if region is not None else '-',
            'tenant': tenant if tenant is not None else '-',
            'prefix': prefix if prefix is not None else '-',
            'aggregate': aggregate if aggregate is not None else '-',
        }
    else:
        res = {
            'ip': ip,
            'region': region,
            'tenant': tenant,
            'prefix': prefix,
            'aggregate': aggregate,
        }
    return res


def make_files(data, event_type, tenant=None, search_tenant=None):
    file_name = ''
    if tenant:
        file_name += tenant + '-'
    else:
        file_name += 'all-'
    if event_type:
        file_name += event_type + '-'

    now = datetime.now() + timedelta(hours=3)
    now.strftime("%d.%m.%Y %H:%M")
    file_name += now.strftime("%d.%m.%Y_%H:%M")

    file_name_csv = file_name + '.csv'
    with open(file_name_csv, 'w', newline='', encoding='utf-8') as f:
        # fieldnames = ['region', 'status', 'threat', 'source', 'target', 'tenant', 'timestamp']
        wr = csv.writer(f)
        wr.writerow(data['fieldnames'])
        ips_dict = {}
        for rec in data['source']:
            if rec[2]:
                if not(rec[2] in ips_dict.keys()):
                    tenant_name = get_data_from_ipam(rec[2])
                    ips_dict[rec[2]] = str(tenant_name['tenant'])
                rec.append(ips_dict[rec[2]])
                rec[3], rec[4], rec[5], rec[6], rec[7] = rec[7], rec[3], rec[4], rec[5], rec[6]
            wr.writerow(rec)
    file_name_xls = file_name + '.xls'
    x_data = []
    x_data.append(data['fieldnames'])
    for rec in data['source']:
        x_data.append(rec)
    try:
        pyexcel.save_as(array=x_data, dest_file_name=file_name_xls)
    except Exception as e:
        print(e)

    return file_name_csv, file_name_xls


@try_repeat
def get_tenant_attacks(tenant=None, top50=False):
    es = connect_elk(quiet=True)
    body = get_elk_request_body(tenant)
    data = es.search(index='kasper*', body=body, size=10000, request_timeout=40)
    if 'hits' in data:
        if 'hits' in data['hits']:
            hits = data['hits']['hits']
            if len(hits) == 0:
                print('Tenant not found. -3')
                return None, None
        else:
            print('Tenant not found. -2')
            return None, None
    else:
        print('Tenant not found. -1')
        return None, None

    rec_attack_info = []
    for e, rec in enumerate(hits):
        # print(e)
        rec_info = []
        if e == 50 and top50:
            break
        if not top50 and rec['_source']['region'] != tenant:
            continue
        rec_info.append(rec['_source']['region'])
        rec_info.append(rec['_source']['sd']['event']['etdn'])
        rec_info.append(rec['_source']['sd']['event']['p1'])
        rec_info.append(rec['_source']['attack_source_ip'])
        rec_info.append(rec['_source']['attack_target_ip'])
        rec_info.append(rec['_source']['mchs_organisation'])
        rec_info.append(rec['_source']['@timestamp'])
        rec_attack_info.append(rec_info)
    if len(rec_attack_info) == 0:
        return -4
    fieldnames = ['Регион', 'Статус', 'Угроза', 'Источник', 'Цель', 'Учреждение', 'Дата']
    data = {
        'fieldnames': fieldnames,
        'source': rec_attack_info
    }
    f_name_csv, f_name_xls = make_files(data, 'attacks', tenant)
    return f_name_csv, f_name_xls


@try_repeat
def get_all_attacks():
    es = connect_elk(quiet=True)
    body = get_elk_request_body(all_attacks=True)
    try:
        data = es.search(index='kasper*', body=body, size=10000, request_timeout=40)
    except Exception as e:
        raise Exception(e)

    hits = data['hits']['hits']
    if not hits:
        return None
    arr = []
    for hit in hits:
        region = attack = attack_count = tenant = None
        date = hit['_source']['@timestamp'].split('.')[0]
        try:
            region = hit['_source']['region']
        except Exception as e:
            print('ERROR region: ', e)
        try:
            attack = hit['_source']['sd']['event']['p1']
        except Exception as e:
            print('ERROR attack_target_ip: ', e)
        arr.append(f"{region}, {attack}")
    es.close()
    counter = Counter(arr)
    q = sorted(counter.items(), key=lambda i: i[1], reverse=True)
    # print()
    result = []
    for row in q:
        result.append(f"Регион: {row[0].split(',')[0]}\n"
                      f"Тип атаки:\n"
                      f"{row[0].split(',')[1]}\n"
                      f"Колличество атак: {row[1]}\n")
    return result


@try_repeat
def get_stats():
    es = connect_elk(quiet=True)
    body = get_elk_request_body(stats=True)
    try:
        data = es.search(index='kasper*', body=body, size=10000, request_timeout=40)
    except Exception as e:
        raise Exception(e)

    hits = data['hits']['hits']
    if not hits:
        print()
    arr = []
    count_attacks = len(hits)
    regions = []
    sources = []
    targets = []
    for hit in hits:
        region = source_ip = target_ip = None
        region = hit['_source']['region']
        source_ip = hit['_source']['attack_source_ip']
        target_ip = hit['_source']['attack_target_ip']
        regions.append(region)
        sources.append(source_ip)
        targets.append(target_ip)
    count_regions = len(list(set(regions)))
    count_sources = len(list(set(sources)))
    count_targets = len(list(set(targets)))
    es.close()
    return count_regions, count_attacks, count_sources, count_targets


@try_repeat
def get_all_events(tenant=None):
    es = connect_elk(quiet=True)
    body = get_elk_request_body(events=True)
    try:
        data = es.search(index='logstash*', body=body, size=1000, request_timeout=40)
    except Exception as e:
        raise Exception(e)
    buckets = data['aggregations']['2']['buckets']
    es.close()
    if not buckets:
        print('No data')
    buckets = sorted(buckets, key=lambda x: x['doc_count'], reverse=True)
    arr = []
    users_arr = []
    for bucket in buckets:
        users_arr = []
        region = bucket['key']
        all_events_counts = bucket['doc_count']
        if all_events_counts < 30:
            continue
        flag = False
        for user in bucket['6']['buckets']:
            if user['doc_count'] <= 30 and not (str(user['key']).upper() in ['USER', 'ADMIN']):
                continue
            users_arr.append([user['key'], user['7']['buckets'][0]['key'], user['doc_count']])
            flag = True
        if flag:
            message = f'Регион: {region}\n' \
                  f'Событий: {all_events_counts}\n'  # f'Код события: {event}\n' \
        users_arr = sorted(users_arr, key=itemgetter(2), reverse=True)
        if users_arr:
            for user in users_arr:
                appended = ''
                if user[1] != '-':
                    appended = f"{user[0]} ({user[1]}): {user[2]} попыток\n"
                else:
                    appended = f"{user[0]}: {user[2]} попыток\n"
                if appended:
                    message += appended

        arr.append(message)
    return arr[:10]


@try_repeat
def get_stats_event():
    es = connect_elk(quiet=True)
    body_arms, body = get_elk_request_body(stats_event=True)
    try:
        data = es.search(index='logstash*', body=body, size=100, request_timeout=40)
    except Exception as e:
        raise Exception(e)
    count_4624 = int(data['aggregations']['4']['buckets'][0]['doc_count'])
    count_4625 = int(data['aggregations']['4']['buckets'][1]['doc_count'])
    count_4627 = int(data['aggregations']['4']['buckets'][2]['doc_count'])
    try:
        data = es.search(index='logstash*', body=body_arms, size=100, request_timeout=40)
    except Exception as e:
        raise Exception(e)
    print()
    es.close()
    region_count = int(data['aggregations']['1']['value'])
    arms_count = int(data['aggregations']['2']['value'])

    return count_4624, count_4625, count_4627, region_count, arms_count


@try_repeat
def get_change_privilege_events():
    """
    Получить свсе события за 24 часа "Повышение привилегий" "
    """
    es = connect_elk(quiet=True)
    body = get_elk_request_body(previlege=True)
    try:
        data = es.search(index='logstash*', body=body, size=1000, request_timeout=40)
    except Exception as e:
        raise Exception(e)
    hits = data['hits']['hits']
    es.close()
    if not hits:
        return None
    result = {}
    for hit in hits:
        event_code = agent_name = region = message = username = group_name = user_description = None
        date = hit['_source']['@timestamp'].split('.')[0]
        region = hit['_source']['region']
        event_code = hit['_source']['event']['code']
        agent_name = hit['_source']['agent']['name']
        message = hit['_source']['short_message']
        username = hit['_source']['winlog']['event_data']['SubjectUserName']
        group_name = hit['_source']['winlog']['event_data']['TargetUserName']
        user_description = hit['_source']['winlog']['event_data']['MemberName']

        if region in result.keys():
            result[region].append([date, event_code, message, agent_name, username, group_name, user_description])
        else:
            result[region] = [[date, event_code, message, agent_name, username, group_name, user_description]]

    return result


@try_repeat
def get_vpo_events(tenant=None, days=None):
    """
    Получить свсе события за 24 часа только критических ВПО. Список критических ВПО в отдельном файле vpo.txt
    """
    es = connect_elk(quiet=True)
    if tenant:
        body = get_elk_request_body(tenant, vpo=True, days=days)
    else:
        body = get_elk_request_body(vpo=True)
    try:
        data = es.search(index='kasper*', body=body, size=1000, request_timeout=40)
    except Exception as e:
        raise Exception(e)
    hits = data['hits']['hits']
    es.close()
    if not hits:
        if tenant:
            return None, None
        return None
    cleared_vpo = []
    result = {}
    for hit in hits:
        try:
            ip = hostname = region = message = vpo = group_name = user_description = None
            date = hit['_source']['@timestamp'].split('.')[0].replace('T', ' ')
            message = hit['_source']['sd']['event']['etdn']
            region = hit['_source']['region']
            ip = hit['_source']['sd']['event']['hip']
            hostname = hit['_source']['sd']['event']['hdn']
            vpo = hit['_source']['sd']['event']['p5']
            path = hit['_source']['sd']['event']['p2']

            if str(message).strip() == 'Объект удален':
                cleared_vpo.append(path)
                continue
            if tenant:
                if region in result.keys():
                    result[region].append([date, region, ip, hostname, vpo, path, message])
                else:
                    result[region] = [[date, region, ip, hostname, vpo, path, message]]
            else:
                if region in result.keys():
                    for _ip in result[region]:
                        if ip in _ip.keys():
                            for _hostname in _ip[ip]:
                                if hostname in _hostname.keys():
                                    _hostname[hostname].append(vpo)
                                    _hostname[hostname] = list(set(_hostname[hostname]))
                                else:
                                    _hostname[hostname] = [vpo]
                        else:
                            result[region].append(
                                {ip: [{
                                    hostname: [vpo]}]}
                            )

                else:
                    result[region] = [{
                        ip: [{
                            hostname: [vpo]
                        }]
                    }]

        except Exception as e:
            print(e)
    for val in result.values():
        for num, event in enumerate(val):
            for cleared_path in cleared_vpo:
                if cleared_path in event[5]:
                    val.pop(num)
                    num -= 1
    if tenant:
        if not result[tenant]:
            return "Clear", "Clear"
        fieldnames = ['Дата', 'Регион', 'IP-адрес источника', 'Имя АРМ-а', 'ВПО', 'Путь', 'Сообщение']
        data = {
            'fieldnames': fieldnames,
            'source': result[tenant]
        }
        return make_files(data, 'vpo', tenant)
    return result


def get_stat():
    try:
        now = datetime.now() + timedelta(hours=3)
        message = ''
        table = get_all_attacks()
        sleep(0.5)
        top_events = get_all_events()
        sleep(0.5)
        groups_privilege = get_change_privilege_events()
        sleep(0.5)
        vpo = get_vpo_events()
        count_regions, count_attacks, count_sources, count_targets = get_stats()
        if not (count_regions == count_attacks == count_sources == count_targets == 0):
            message = f'*__Сводка событий безопасности на {now.strftime("%d.%m.%Y %H:%M")} за 24 часа:__*\n\n'

        if table:
            message += f"*События \"Сетевые атаки\":*\n" \
                       f"Учреждений с атаками: {count_regions}\n" \
                       f"Всего атак: {count_attacks}\n" \
                       f"Атакующих: {count_sources}\n" \
                       f"Атакованных: {count_targets}\n\n"
            for row in table:
                message += row + '\n'
        count_4624, count_4625, count_4627, region_count, arms_count = get_stats_event()
        message += f"\n*События 4625 (неуспешный вход в систему):*\n" \
                   f"Учреждений : {region_count}\n" \
                   f"АРМов: {arms_count}\n" \
                   f"Событий с кодом 4625: {count_4625}\n\n"
        for row in top_events:
            message += row + '\n'
        if vpo:
            message += f"\n*События \"Обнаружен вредоносный объект\":*"
            for gu, data in vpo.items():
                message += f'\n*Регион: {gu}*\n'
                for _ip in data:
                    try:
                        for ip, hostnames in _ip.items():
                            for hostname in hostnames:
                                for hn, vpos in hostname.items():
                                    count_vpos = "".join(vpos) if len(vpos) == 1 else len(vpos)
                                    message += f'АРМ: {hn} ({ip})\n' \
                                               f'Обнаружено ВПО: {str(count_vpos) + " видов(а)" if isinstance(count_vpos, int) else count_vpos}\n'
                    except Exception as e:
                        print(e)
        if groups_privilege:
            try:
                user_name_reg = re.compile(r'[Cc][Nn]=([\w\s\.\-\_]+)')
                message += f"\n\n*События \"Изменение привилегий\":*"
                for gu, data in groups_privilege.items():
                    message += f'\n*Регион: {gu}*'
                    for item in data:
                        state = None
                        if item[1] == 4728:
                            state = "Добавление пользователя"
                        elif item[1] == 4729:
                            state = "Удаление пользователя"
                        elif item[1] == 4727:
                            state = "Создана группа с поддержкой безопасности"
                        elif item[1] == 4730:
                            state = "Группа с поддержкой безопасности удалена"
                        message += f'\n{item[0].replace("T", " ")}: {item[1]} ({state if state else item[2]})\n' \
                                   f'Кто: {item[4]}\n' \
                                   f'Кого: {re.search(user_name_reg, item[6]).group(1)}\n' \
                                   f'Группа: {item[5]}\n\n'
            except Exception as e:
                print(e)
        return message
    except Exception as e:
        print(e)
        return None


def get_gu_ad_stat(tenant):
    es = connect_elk(quiet=True)
    body = get_elk_request_body(tenant, gu_ad=True)
    try:
        data = es.search(index='logstash*', body=body, size=50, request_timeout=40)
    except Exception as e:
        raise Exception(e)

    if 'hits' in data:
        if 'hits' in data['hits']:
            hits = data['hits']['hits']
            if len(hits) == 0:
                print('Tenant not found. -3')
                return None, None
        else:
            print('Tenant not found. -2')
            return None, None
    else:
        print('Tenant not found. -1')
        return None, None

    if not hits:
        print(-1)
    out_arr = []
    for hit in hits:
        src = hit['_source']
        out_row = []
        out_row.append(src['@timestamp'])
        out_row.append(src['region'])
        out_row.append(src['winlog']['event_data']['IpAddress'])
        out_row.append(src['winlog']['event_data']['IpPort'])
        out_row.append(src['winlog']['event_data']['TargetUserName'])
        out_row.append(src['host']['name'])
        try:
            work_st = src['winlog']['event_data']['WorkstationName']
        except:
            work_st = '-'
        out_row.append(work_st)
        #out_row.append(src['winlog']['event_data']['WorkstationName'])
        out_arr.append(out_row)
    es.close()
    fieldnames = ['Дата', 'Регион', 'IP-адрес источника', 'ГУ Источника', 'Порт подключения', 'Имя учётной записи', 'Имя сервера', 'Имя АРМ-а']
    data = {
        'fieldnames': fieldnames,
        'source': out_arr
    }
    f_name_csv, f_name_xls = make_files(data, 'ad', tenant, search_tenant=True)
    return f_name_csv, f_name_xls


def make_date(delta=None):
    if delta is None:
        delta = 30
    today = datetime.now()
    yesterday = datetime.now() - timedelta(days=delta)

    return today.strftime('%Y-%m-%dT21:00:00.000Z'), yesterday.strftime('%Y-%m-%dT20:59:59.000Z')


def make_human_date(string: str):
    date = string.split('.')[0]
    _date = datetime.strptime(date, '%Y-%m-%dT%H:%M:%S')
    date = datetime.strftime(_date, '%Y-%m-%d %H:%M')
    return date


@try_repeat
def check_in_sed(ip):
    es = connect_elk()
    body = get_elk_request_body(ip=ip, sed=True)
    res = es.search(index='logstash*', body=body, size=100, request_timeout=40)
    if res['hits']['hits']:
        data_list = []
        hits = res['hits']['hits']
        for hit in hits:
            data = hit['_source']
            name = org = agent = None
            date = make_human_date(data['@timestamp'])
            try:
                name = data['user_fio']
            except:
                pass
            if name is None:
                try:
                    name = data['user_name']
                except:
                    pass
            try:
                org = data['user_org']
                agent = data['user_agent']
            except:
                pass
            data_list.append([date, name, org, agent])
        return data_list
    else:
        return False


# if __name__ == '__main__':
#     get_gu_ad_stat('')


