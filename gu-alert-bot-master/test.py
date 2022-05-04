from utils import *


def get_events_group_changes():
    es = connect_elk(quiet=True)
    body = get_body(group_changes=True)
    try:
        data = es.search(index='logstash*', body=body, size=10000, request_timeout=40)
    except Exception as e:
        raise Exception(e)
    hits = data['hits']['hits']
    if not hits:
        return None
    arr = []
    for hit in hits:
        region = dc_name = admin_name = group_name = account_name = None
        date = make_human_date(hit['_source']['@timestamp'])
        region = hit['_source']['region']
        dc_name = hit['_source']['agent']['name']
        admin_name = hit['_source']['winlog']['event_data']['SubjectUserName']
        group_name = hit['_source']['winlog']['event_data']['TargetUserName']
        account_name = hit['_source']['winlog']['event_data']['MemberName']
        arr.append([date, region, dc_name, admin_name, group_name, account_name])
    # ['2022-03-09 11:05', '78-GU-DC', 'SPB-SZFO-DC0', 'ovcharenko.b.v', 'DC_Admins', 'cn=Кочеров Андрей Валерьевич,OU=УИТС,OU=Users,OU=SPB-GU-OU,DC=szrc,DC=mchs,DC=ru']
    return arr


IPAM_TOKEN = ""
IPAM_URL = ''


def connect_ipam():
    token = IPAM_TOKEN
    url = IPAM_URL

    nb = pynetbox.api(
        url,
        token=token,
        threading=True,
    )
    return nb


def get_data_from_ipam(ip, nb):
    tenant = None
    region = None
    prefix = None
    aggregate = None
    tenant_id = None
    try:
        q = nb.ipam.ip_addresses.get(address=ip)
        try:
            prefix = nb.ipam.prefixes.get(q=ip)
            address = str(prefix.site.region.name) + ' ' + str(prefix.site.name)
        except:
            prefixes = nb.ipam.prefixes.filter(q=ip)
            for item in prefixes:
                prefix = item
                tenant = prefix.tenant
                break
        aggregate = nb.ipam.aggregates.get(q=prefix.prefix)
        if tenant is None:
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
        aggregate = nb.ipam.aggregates.get(q=ip)
        q = None
    if q is None:
        res = {
            'ip': ip,
            'prefix': prefix if prefix is not None else 'нет в IPAM',
            'aggregate': aggregate if aggregate is not None else 'нет в IPAM',
            'tenant': tenant if tenant is not None else 'нет в IPAM',
            'tenant_id': tenant.id if tenant is not None else 'нет в IPAM',
        }
    else:
        try:
            id = tenant.id
        except:
            id = '-'
        res = {
            'ip': ip,
            'prefix': prefix,
            'aggregate': aggregate,
            'tenant': tenant,
            'tenant_id': id
        }
    return res


if __name__ == '__main__':
    ip = ''
    get_data_from_ipam(ip, connect_ipam())
