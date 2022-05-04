import csv
from collections import Counter
from datetime import datetime, timedelta
from time import sleep

import pyexcel
import pynetbox
from elasticsearch import Elasticsearch, NotFoundError
from prettytable import PrettyTable

# from db_manage import set_all_old, add_item, check_one
from env import ELK_USER, ELK_PASS, ELK_URL, IPAM_TOKEN, IPAM_URL, TIME_TO_SEND


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
    print('Connecting to ipsm.mchs.ru')

    nb = pynetbox.api(
        url,
        token=token
    )
    return nb


def get_time_to_send(timezone):
    now = datetime.now() + timedelta(hours=3)
    if int((now + timedelta(hours=timezone)).strftime("%H")) == TIME_TO_SEND:
        return True
    return False


def exception_print(reg):
    print()
    print("*" * 50)
    print(reg, 'НЕТ В СПИСКЕ ЧАТОВ')
    print("*" * 50)
    print()
    return


def time_to_alarm(timezone):
    now = int((datetime.now() + timedelta(hours=3)).strftime("%H")) + timezone
    if now > 9:
        hours_to_alarm = 24 - now + 9
    else:
        hours_to_alarm = 9 - now
    return hours_to_alarm


def make_date():
    delta = 24
    time_to = datetime.now() + timedelta(hours=3)
    time_at = time_to - timedelta(hours=delta)

    return [time_at.strftime('%Y-%m-%dT%H:%M:00.000Z'), time_to.strftime('%Y-%m-%dT%H:%M:00.000Z')]


def make_human_date(string: str):
    date = string.split('.')[0]
    _date = datetime.strptime(date, '%Y-%m-%dT%H:%M:%S')
    date = datetime.strftime(_date, '%d-%m-%Y %H:%M')
    return date


def make_files(data, event_type, tenant=None):
    file_name = ''
    if tenant:
        file_name += tenant + '-'
    else:
        file_name += 'all-'
    if event_type:
        file_name += event_type + '-'

    now = datetime.now() + timedelta(hours=3)
    file_name += str(now.strftime("%d.%m.%Y_%H:%M"))

    file_name_csv = file_name + '.csv'
    with open(file_name_csv, 'w', newline='', encoding='utf-8') as f:
        # fieldnames = ['region', 'status', 'threat', 'source', 'target', 'tenant', 'timestamp']
        wr = csv.writer(f)
        wr.writerow(data['fieldnames'])
        for rec in data['source']:
            wr.writerow(rec)
    file_name_xls = file_name + '.xls'
    x_data = []
    x_data.append(data['fieldnames'])
    for rec in data['source']:
        x_data.append(rec)

    pyexcel.save_as(array=x_data, dest_file_name=file_name_xls)
    return file_name_csv, file_name_xls


def get_elk_request_body(tenant=None, all_attacks=None, stats=None, events=None, stats_event=None, gu_ad=None):
    date_from, date_to = make_date()
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
    elif gu_ad and tenant:
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
        body = {
            "aggs": {
                "2": {
                    "terms": {
                        "field": "region.keyword",
                        "order": {
                            "_count": "desc"
                        },
                        "size": 15
                    },
                    "aggs": {
                        "3": {
                            "terms": {
                                "field": "short_message.keyword",
                                "order": {
                                    "_count": "desc"
                                },
                                "size": 15
                            },
                            "aggs": {
                                "4": {
                                    "terms": {
                                        "field": "event.code",
                                        "order": {
                                            "_count": "desc"
                                        },
                                        "size": 15
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
                            "match_all": {}
                        },
                        {
                            "match_phrase": {
                                "type": "dc"
                            }
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
                    "must_not": []
                }
            }
        }
        return body
    elif stats_event:
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


def get_body(new_attacks=False, all_attacks=False, events=False, group_changes=False):
    dates = make_date()
    if new_attacks:
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
    elif all_attacks:
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
        body = {
            "aggs": {
                "2": {
                    "terms": {
                        "field": "region.keyword",
                        "order": {
                            "_count": "desc"
                        },
                        "size": 15
                    },
                    "aggs": {
                        "3": {
                            "terms": {
                                "field": "short_message.keyword",
                                "order": {
                                    "_count": "desc"
                                },
                                "size": 15
                            },
                            "aggs": {
                                "4": {
                                    "terms": {
                                        "field": "event.code",
                                        "order": {
                                            "_count": "desc"
                                        },
                                        "size": 15
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
                            "match_all": {}
                        },
                        {
                            "match_phrase": {
                                "type": "dc"
                            }
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
                    "must_not": []
                }
            }
        }
        return body
    elif group_changes:
        body = {
              "aggs": {
                "2": {
                  "terms": {
                    "field": "event.code",
                    "order": {
                      "1": "desc"
                    },
                    "size": 10
                  },
                  "aggs": {
                    "1": {
                      "max": {
                        "field": "@timestamp"
                      }
                    },
                    "3": {
                      "terms": {
                        "field": "agent.name.keyword",
                        "order": {
                          "1": "desc"
                        },
                        "size": 10
                      },
                      "aggs": {
                        "1": {
                          "max": {
                            "field": "@timestamp"
                          }
                        },
                        "4": {
                          "terms": {
                            "script": {
                              "source": "if (doc.containsKey('region.keyword') && !doc['region.keyword'].empty) {\n    def region_value = doc['region.keyword'].value;    \n    return region_value;\n}\ndef region_value = '#';    \nreturn region_value;",
                              "lang": "painless"
                            },
                            "order": {
                              "1": "desc"
                            },
                            "value_type": "string",
                            "size": 10
                          },
                          "aggs": {
                            "1": {
                              "max": {
                                "field": "@timestamp"
                              }
                            },
                            "5": {
                              "terms": {
                                "field": "short_message.keyword",
                                "order": {
                                  "1": "desc"
                                },
                                "size": 10
                              },
                              "aggs": {
                                "1": {
                                  "max": {
                                    "field": "@timestamp"
                                  }
                                },
                                "6": {
                                  "terms": {
                                    "field": "winlog.event_data.SubjectUserName.keyword",
                                    "order": {
                                      "1": "desc"
                                    },
                                    "size": 10
                                  },
                                  "aggs": {
                                    "1": {
                                      "max": {
                                        "field": "@timestamp"
                                      }
                                    },
                                    "7": {
                                      "terms": {
                                        "field": "winlog.event_data.TargetUserName.keyword",
                                        "order": {
                                          "1": "desc"
                                        },
                                        "size": 10
                                      },
                                      "aggs": {
                                        "1": {
                                          "max": {
                                            "field": "@timestamp"
                                          }
                                        },
                                        "8": {
                                          "terms": {
                                            "field": "winlog.event_data.MemberName.keyword",
                                            "order": {
                                              "1": "desc"
                                            },
                                            "size": 10
                                          },
                                          "aggs": {
                                            "1": {
                                              "max": {
                                                "field": "@timestamp"
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
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


@try_repeat
def get_new_attacks():
    es = connect_elk(quiet=True)
    body = get_body(new_attacks=True)
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
    return arr


def get_tenant_by_ip(ip):
    nb = connect_ipam()
    tenant = 'Нет в IPAM'
    try:
        q = nb.ipam.ip_addresses.get(address=ip)
        try:
            prefix = nb.ipam.prefixes.get(q=ip)
        except:
            prefixes = nb.ipam.prefixes.filter(q=ip)
            for item in prefixes:
                prefix = item
                tenant = prefix.tenant
                break
        aggregate = nb.ipam.aggregates.get(q=prefix.prefix)
        if tenant in ['Нет в IPAM', None]:
            try:
                tenant = nb.tenancy.tenants.get(name=q.tenant)
            except:
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
                except:
                    pass
    except:
        pass

    return str(tenant)


@try_repeat
def get_all_attacks():
    es = connect_elk(quiet=True)
    body = get_body(all_attacks=True)
    try:
        data = es.search(index='kasper*', body=body, size=10000, request_timeout=40)
    except Exception as e:
        raise Exception(e)
    es.close()
    hits = data['hits']['hits']
    if not hits:
        return None
    tenant_dict = {}
    arr = []
    ips_dict = {}
    for hit in hits:
        region = attack = None
        date = hit['_source']['@timestamp'].split('.')[0].replace('T', ' ')
        source_ip = hit['_source']['attack_source_ip']
        target_ip = hit['_source']['attack_target_ip']
        target_port = hit['_source']['sd']['event']['p4']
        if source_ip in ips_dict.keys():
            tenant = ips_dict[source_ip]
        else:
            tenant = get_tenant_by_ip(source_ip)
            ips_dict[source_ip] = tenant
        try:
            region = hit['_source']['region']
        except Exception as e:
            print('ERROR region: ', e)
        try:
            attack = hit['_source']['sd']['event']['p1']
        except Exception as e:
            print('ERROR attack_target_ip: ', e)
        arr.append(f"{region}, {attack}")
        if tenant in tenant_dict.keys():
            tenant_dict[tenant].append([date, region, tenant, source_ip, target_ip, target_port, attack])
        else:
            tenant_dict[tenant] = [[date, region, tenant, source_ip, target_ip, target_port, attack]]

    counter = Counter(arr)
    q = sorted(counter.items(), key=lambda i: i[1], reverse=True)
    # print()
    result = []
    for row in q:
        result.append(f"Регион: {row[0].split(',')[0]}\n"
                      f"Тип атаки:\n"
                      f"{(row[0].split(',')[1]).strip()}\n"
                      f"Колличество атак: {row[1]}\n")
    return result, tenant_dict


# get_all_attacks()


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
    arr = []
    count = 0
    for bucket in buckets:
        if count == 10:
            break
        count += 1
        region = bucket['key']
        counts = bucket['doc_count']
        event = bucket['3']['buckets'][0]['4']['buckets'][0]['key']
        arr.append(f'Регион: {region}\n'
                   f'Событий: {counts}\n')
    es.close()
    return arr


@try_repeat
def get_tenant_attacks(tenant=None, top=False):
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
        if top and e == int(top):
            break
        if rec['_source']['region'] != tenant:
            continue
        rec_info.append(rec['_source']['region'])
        rec_info.append(rec['_source']['sd']['event']['etdn'])
        rec_info.append(rec['_source']['sd']['event']['p1'])
        rec_info.append(rec['_source']['attack_source_ip'])
        rec_info.append(rec['_source']['attack_target_ip'])
        rec_info.append(rec['_source']['mchs_organisation'])
        rec_info.append(rec['_source']['@timestamp'])
        rec_attack_info.append(rec_info)
    # print(len(rec_attack_info), '\n', rec_attack_info)
    if len(rec_attack_info) == 0:
        return -4
    # for e, rec in enumerate(rec_attack_info):
    #     print(e+1, rec)
    fieldnames = ['Регион', 'Статус', 'Угроза', 'Источник', 'Цель', 'Учреждение', 'Дата']
    data = {
        'fieldnames': fieldnames,
        'source': rec_attack_info
    }
    f_name_csv, f_name_xls = make_files(data, 'attacks', tenant)
    return f_name_csv, f_name_xls


def get_gu_ad_stat(tenant):
    es = connect_elk(quiet=True)
    body = get_elk_request_body(tenant, gu_ad=True)
    try:
        data = es.search(index='logstash*', body=body, size=500, request_timeout=40)
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
    fieldnames = ['Дата', 'Регион', 'IP-адрес источника', 'Порт подключения', 'Имя учётной записи', 'Имя сервера', 'Имя АРМ-а']
    data = {
        'fieldnames': fieldnames,
        'source': out_arr
    }
    f_name_csv, f_name_xls = make_files(data, 'ad', tenant)
    return f_name_csv, f_name_xls


# if __name__ == '__main__':
#     from env import TOP, CHATS
#     chat_dict = CHATS
#     attacks, attacks_by_tenants = get_all_attacks()
