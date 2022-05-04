from collections import Counter
from datetime import datetime, timedelta
from operator import itemgetter

import pynetbox
from elasticsearch import Elasticsearch, NotFoundError
from prettytable import PrettyTable

from db_manage import set_all_old, add_item, check_one
from env import ELK_USER, ELK_PASS, ELK_URL, IPAM_TOKEN, IPAM_URL


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
                print('ReConnect...')
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


def connect_ipam():
    token = IPAM_TOKEN
    url = IPAM_URL
    nb = pynetbox.api(
        url,
        token=token
    )
    return nb


def make_date(all_attacks=None):
    time_to = datetime.now()  # - timedelta(hours=3)
    if all_attacks:
        # time_at = time_to - timedelta(days=14)
        time_at = time_to - timedelta(days=1)
    else:
        time_at = time_to - timedelta(minutes=15)
        # time_at = time_to - timedelta(days=30)

    return [time_at.strftime('%Y-%m-%dT%H:%M:00.000Z'), time_to.strftime('%Y-%m-%dT%H:%M:00.000Z')]


def get_body(mssec=None, all_attacks=None, stats=None, events=None, stats_event=None, previlege=None, vpo=None):
    dates = make_date()
    if mssec:
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
                        "time_zone": "UTC",
                        "min_doc_count": 1
                    }
                }
            },
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
                            "bool": {
                                "should": [
                                    {
                                        "multi_match": {
                                            "type": "phrase",
                                            "query": "mssecsvc.exe",
                                            "lenient": True
                                        }
                                    },
                                    {
                                        "multi_match": {
                                            "type": "phrase",
                                            "query": "mssecsvr.exe",
                                            "lenient": True
                                        }
                                    }
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        {
                            "exists": {
                                "field": "all_connections.name"
                            }
                        },
                        {
                            "exists": {
                                "field": "all_connections.local_address"
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"{dates[0]}",
                                    "lte": f"{dates[1]}",
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
    elif stats:
        dates = make_date(all_attacks=True)
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
                                    "gte": f"{dates[0]}",
                                    "lte": f"{dates[1]}",
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
    elif all_attacks:
        dates = make_date(all_attacks=True)
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
                                    "gte": f"{dates[0]}",
                                    "lte": f"{dates[1]}",
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
    elif events:
        dates = make_date(all_attacks=True)
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
                                    "gte": f"{dates[0]}",
                                    "lte": f"{dates[1]}",
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
        dates = make_date(all_attacks=True)
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
                  "bool": {
                    "should": [
                      {
                        "script": {
                          "script": {
                            "source": "boolean compare(Supplier s, def v) {return s.get() == v;}compare(() -> { if (doc.containsKey('winlog.event_data.TargetUserName.keyword') && !doc['winlog.event_data.TargetUserName.keyword'].empty) {\n    if (doc['winlog.event_data.TargetUserName.keyword'].value =~ /^.*\\$$/) {\n        return false;\n    } else {\n        return true;\n    }\n}\nreturn false; }, params.value);",
                            "lang": "painless",
                            "params": {
                              "value": True
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
                      "gte": f"{dates[0]}",
                      "lte": f"{dates[1]}",
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
            "user_logon_only": {
              "script": {
                "source": "if (doc.containsKey('winlog.event_data.TargetUserName.keyword') && !doc['winlog.event_data.TargetUserName.keyword'].empty) {\n    if (doc['winlog.event_data.TargetUserName.keyword'].value =~ /^.*\\$$/) {\n        return false;\n    } else {\n        return true;\n    }\n}\nreturn false;",
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
                            "source": "boolean compare(Supplier s, def v) {return s.get() == v;}compare(() -> { if (doc.containsKey('winlog.event_data.TargetUserName.keyword') && !doc['winlog.event_data.TargetUserName.keyword'].empty) {\n    if (doc['winlog.event_data.TargetUserName.keyword'].value =~ /^.*\\$$/) {\n        return false;\n    } else {\n        return true;\n    }\n}\nreturn false; }, params.value);",
                            "lang": "painless",
                            "params": {
                              "value": True
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
                      "gte": f"{dates[0]}",
                      "lte": f"{dates[1]}",
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
    elif previlege:
        dates = make_date(all_attacks=True)
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
                                    "gte": f"{dates[0]}",
                                    "lte": f"{dates[1]}",
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
    elif vpo:
        dates = make_date(all_attacks=True)
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
                                "gte": f"{dates[0]}",
                                "lte": f"{dates[1]}",
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
                    "time_zone": "UTC",
                    "min_doc_count": 1
                }
            }
        },
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
                        "bool": {
                            "filter": [
                                {
                                    "bool": {
                                        "must_not": {
                                            "bool": {
                                                "should": [
                                                    {
                                                        "query_string": {
                                                            "fields": [
                                                                "attack_source_ip"
                                                            ],
                                                            "query": "\\1\\0\\.*"
                                                        }
                                                    }
                                                ],
                                                "minimum_should_match": 1
                                            }
                                        }
                                    }
                                },
                                {
                                    "bool": {
                                        "filter": [
                                            {
                                                "bool": {
                                                    "must_not": {
                                                        "bool": {
                                                            "should": [
                                                                {
                                                                    "query_string": {
                                                                        "fields": [
                                                                            "attack_source_ip"
                                                                        ],
                                                                        "query": "\\1\\9\\2\\.\\1\\6\\8\\.*"
                                                                    }
                                                                }
                                                            ],
                                                            "minimum_should_match": 1
                                                        }
                                                    }
                                                }
                                            },
                                            {
                                                "bool": {
                                                    "must_not": {
                                                        "bool": {
                                                            "should": [
                                                                {
                                                                    "query_string": {
                                                                        "fields": [
                                                                            "attack_target_ip"
                                                                        ],
                                                                        "query": "\\1\\7\\2\\.*"
                                                                    }
                                                                }
                                                            ],
                                                            "minimum_should_match": 1
                                                        }
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "exists": {
                            "field": "attack_source_ip"
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"{dates[0]}",
                                "lte": f"{dates[1]}",
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
                            "sd.event.p1": "Scan.Generic.PortScan.TCP"
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


def create_data_or_remove(arr: list, mssec=False):
    if mssec:
        table = 'sc_events_mssec'
        set_all_old(table)
        to_del = []
        for i in range(len(arr)):
            if check_one(arr[i], table, mssec=mssec):
                to_del.append(i)
                continue
            else:
                add_item(arr[i], table, mssec=mssec)
                # print(f'{arr[i]}\n has been added!')
        to_del = list(set(to_del))
        for item in to_del[::-1]:
            arr.pop(item)
    else:
        table = 'sc_events'
        set_all_old(table)
        to_del = []
        for i in range(len(arr)):
            if check_one(arr[i], table):
                to_del.append(i)
                continue
            else:
                add_item(arr[i], table)
                # print(f'{arr[i]}\n has been added!')
        for item in to_del[::-1]:
            arr.pop(item)
    return arr


@try_repeat
def get_new_alarms_kasper():
    es = connect_elk(quiet=True)
    body = get_body()
    try:
        data = es.search(index='kasper*', body=body, size=10000, request_timeout=40)
    except Exception as e:
        raise Exception(e)

    hits = data['hits']['hits']
    if not hits:
        return None
    count = 0
    arr = []
    for hit in hits:
        attack_source_ip = attack_target_ip = syslog_hostname = alert = date = event = port = protocol = None
        date = hit['_source']['@timestamp'].split('.')[0]
        try:
            attack_source_ip = hit['_source']['attack_source_ip']
        except Exception as e:
            print('ERROR atac_source_ip: ', e)
        try:
            attack_target_ip = hit['_source']['attack_target_ip']
            port = hit['_source']['sd']['event']['p4']
            protocol = hit['_source']['sd']['event']['p2']
        except Exception as e:
            print('ERROR attack_target_ip: ', e)
        count += 1
        try:
            syslog_hostname = hit['_source']['syslog_hostname']
        except:
            pass
        try:
            alert = hit['_source']['sd']['event']['etdn']
        except:
            pass
        try:
            event = hit['_source']['sd']['event']['p1']
        except:
            pass
        try:
            region = hit['_source']['region']
        except:
            pass
        arr.append([date, alert, attack_source_ip, attack_target_ip, port, protocol, syslog_hostname, event, region])
    es.close()
    if arr:
        result = create_data_or_remove(arr)
    return result


@try_repeat
def get_new_alarms_mssec():
    es = connect_elk(quiet=True)
    body = get_body(mssec=True)
    try:
        data = es.search(index='osquery*', body=body, size=10000, request_timeout=40)
    except Exception as e:
        raise Exception(e)
    hits = data['hits']['hits']
    if not hits:
        return None
    count = 0
    arr = []
    for hit in hits:
        tenant = hostname = local_address = remote_address = remote_port = state = name = avz_install = szi_install = None
        date = hit['_source']['@timestamp'].split('.')[0]
        try:
            tenant = hit['_source']['mchs_organisation']
        except Exception as e:
            print('ERROR mchs_organisation: ', e)
        try:
            hostname = hit['_source']['hostname']
        except:
            pass
        try:
            local_address = hit['_source']['all_connections']['local_address']
        except Exception as e:
            print('ERROR local_address: ', e)
        try:
            remote_address = hit['_source']['all_connections']['remote_address']
            remote_port = hit['_source']['all_connections']['remote_port']
            state = hit['_source']['all_connections']['state']
        except Exception as e:
            print('ERROR remote_address: ', e)
        count += 1
        try:
            name = hit['_source']['all_connections']['name']
        except:
            pass
        try:
            avz_install = hit['_source']['avz_install']
            szi_install = hit['_source']['szi_install']
        except:
            pass
        arr.append([date, tenant, hostname, local_address, remote_address, remote_port, state, name, avz_install, szi_install])
    es.close()
    if arr:
        result = create_data_or_remove(arr, mssec=True)
        return result


@try_repeat
def get_all_attacks():
    es = connect_elk(quiet=True)
    body = get_body(all_attacks=True)
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
                      f"{str(row[0].split(',')[1]).strip()}\n"
                      f"Колличество атак: {row[1]}\n")
    return result


@try_repeat
def get_stats():
    es = connect_elk(quiet=True)
    body = get_body(stats=True)
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
def get_all_events():
    es = connect_elk(quiet=True)
    body = get_body(events=True)
    try:
        data = es.search(index='logstash*', body=body, size=100, request_timeout=40)
    except Exception as e:
        raise Exception(e)
    buckets = data['aggregations']['2']['buckets']
    if not buckets:
        print('No data')
    buckets = sorted(buckets, key=lambda x: x['doc_count'], reverse=True)
    arr = []
    for bucket in buckets:
        users_arr = []
        region = bucket['key']
        all_events_counts = bucket['doc_count']
        if bucket['doc_count'] < 30:
            continue
        for user in bucket['6']['buckets']:
            if user['doc_count'] <= 30 and not (str(user['key']).upper() in ['USER', 'ADMIN']):
                continue
            users_arr.append([user['key'], user['7']['buckets'][0]['key'], user['doc_count']])
        # event = bucket['6']['buckets'][0]['7']['buckets'][0]['8']['buckets'][0]['9']['buckets'][0]['key']
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
    es.close()
    return arr[:10]


@try_repeat
def get_stats_event():
    es = connect_elk(quiet=True)
    body_arms, body = get_body(stats_event=True)
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
    region_count = int(data['aggregations']['1']['value'])
    arms_count = int(data['aggregations']['2']['value'])
    es.close()
    return count_4624, count_4625, count_4627, region_count, arms_count


@try_repeat
def get_change_privilege_events():
    """
    Получить свсе события за 24 часа "Повышение привилегий" "
    """
    es = connect_elk(quiet=True)
    body = get_body(previlege=True)
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
        event_code = agent_name = region = message = admin_name = group_name = user_description = None
        date = hit['_source']['@timestamp'].split('.')[0]
        region = hit['_source']['region']
        event_code = hit['_source']['event']['code']
        agent_name = hit['_source']['agent']['name']
        message = hit['_source']['short_message']
        admin_name = hit['_source']['winlog']['event_data']['SubjectUserName']
        group_name = hit['_source']['winlog']['event_data']['TargetUserName']
        user_description = hit['_source']['winlog']['event_data']['MemberName']

        if region in result.keys():
            result[region].append([date, event_code, message, agent_name, admin_name, group_name, user_description])
        else:
            result[region] = [[date, event_code, message, agent_name, admin_name, group_name, user_description]]

    return result


@try_repeat
def get_vpo_events():
    """
    Получить свсе события за 24 часа только критических ВПО. Список критических ВПО в отдельном файле vpo.txt
    """
    es = connect_elk(quiet=True)
    body = get_body(vpo=True)
    try:
        data = es.search(index='kasper*', body=body, size=1000, request_timeout=40)
    except Exception as e:
        raise Exception(e)
    hits = data['hits']['hits']
    es.close()
    if not hits:
        return None
    result = {}
    for hit in hits:
        try:
            ip = hostname = region = message = vpo = group_name = user_description = None
            date = hit['_source']['@timestamp'].split('.')[0]
            region = hit['_source']['region']
            ip = hit['_source']['sd']['event']['hip']
            hostname = hit['_source']['sd']['event']['hdn']
            message = hit['_source']['sd']['event']['etdn']
            vpo = hit['_source']['sd']['event']['p5']
            path = hit['_source']['sd']['event']['p2']

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

    return result


# if __name__ == '__main__':
#     message = ''
#     vpo = get_vpo_events()

