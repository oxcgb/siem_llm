import React, {
  useState, useEffect, useMemo
} from 'react';
import {
  Button, Card, Input,
  Select, Table, Tag,
  Space, Typography,
  message
} from 'antd';
import {
  BugOutlined,
  DownloadOutlined,
  ReloadOutlined
} from '@ant-design/icons';
import dayjs from 'dayjs';
import api from '../api';
import { fmtTime } from '../time';

const { Text } = Typography;

export default function Incidents() {
  const [inc, setInc] = useState([]);
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] =
    useState('all');
  const [busy, setBusy] = useState(false);

  const load = () =>
    api('/api/incidents', {
      timeout: 60000
    })
      .then(d =>
        setInc(
          d?.incidents || []))
      .catch(() => {});

  useEffect(() => {
    load();
  }, []);

  const filtered = useMemo(() => {
    let d = inc;
    if (sevFilter !== 'all') {
      d = d.filter(e =>
        e.severity === sevFilter);
    }
    if (search) {
      const s =
        search.toLowerCase();
      d = d.filter(e =>
        (e.username || '')
          .toLowerCase()
          .includes(s));
    }
    return d;
  }, [inc, search, sevFilter]);

  const analyze = async () => {
    setBusy(true);
    message.loading({
      content: 'AI Triage...',
      key: 'ai',
      duration: 0
    });
    try {
      const names =
        filtered.map(
          i => i.username);
      const res = await api(
        '/api/incidents/analyze', {
          method: 'POST',
          body: {
            usernames: names
          },
          timeout: 600000
        }
      );
      const map = new Map(
        inc.map(i =>
          [i.username, i]));
      (res.incidents || [])
        .forEach(a => {
          const prev =
            map.get(a.username)
            || {};
          map.set(a.username, {
            ...prev, ...a
          });
        });
      setInc(
        [...map.values()]);
      message.success({
        content: 'Done',
        key: 'ai'
      });
    } catch (e) {
      message.error({
        content: 'Failed: ' +
          e.message,
        key: 'ai',
        duration: 5
      });
    }
    setBusy(false);
  };

  const exportCsv = () => {
    if (!filtered.length) {
      return;
    }
    const cols = [
      'username', 'severity',
      'risk_score', 'ai_verdict',
      'ai_reason', 'last_seen'
    ];
    const head =
      cols.join(',');
    const lines =
      filtered.map(r =>
        cols.map(c =>
          '"' + String(
            r[c] ?? ''
          ).replace(
            /"/g, '""'
          ) + '"'
        ).join(','));
    const blob = new Blob(
      [[head, ...lines]
        .join('\n')],
      {
        type:
          'text/csv;charset=utf-8'
      });
    const a =
      document.createElement(
        'a');
    a.href =
      URL.createObjectURL(
        blob);
    a.download =
      'incidents_' +
      dayjs().format(
        'YYYYMMDD_HHmm') +
      '.csv';
    a.click();
  };

  const flags = (r) => {
    const tags = [];
    if (r.off_hours) {
      tags.push(
        <Tag key="oh"
          color="volcano">
          Off-hours
        </Tag>
      );
    }
    if (r.multi_geo) {
      tags.push(
        <Tag key="mg"
          color="magenta">
          Multi-geo
        </Tag>
      );
    }
    if (r.ad_without_vpn) {
      tags.push(
        <Tag key="nv"
          color="gold">
          AD w/o VPN
        </Tag>
      );
    }
    if (r.failed_logins) {
      tags.push(
        <Tag key="fl"
          color="red">
          {r.failed_logins}
          {' failed'}
        </Tag>
      );
    }
    if (tags.length) {
      return (
        <Space
          size={4}
          wrap>
          {tags}
        </Space>
      );
    }
    return (
      <Text
        type="secondary">
        —
      </Text>
    );
  };

  const cols = [
    {
      title: 'Username',
      dataIndex:
        'username',
      width: 150,
      fixed: 'left'
    },
    {
      title: 'Severity',
      dataIndex:
        'severity',
      width: 125,
      sorter: (a, b) =>
        (b.risk_score || 0) -
        (a.risk_score || 0),
      render: (v, r) => (
        <Tag color={
          v === 'high'
            ? 'red' :
          v === 'medium'
            ? 'orange' :
          v === 'low'
            ? 'blue' :
          'default'
        }>
          {v} · {r.risk_score}
        </Tag>
      )
    },
    {
      title: 'Signals',
      key: 'flags',
      width: 220,
      render: flags
    },
    {
      title: 'AI Verdict',
      dataIndex:
        'ai_verdict',
      width: 110,
      render: v => {
        if (!v ||
            v === 'not_analyzed') {
          return (
            <Tag>—</Tag>
          );
        }
        const c =
          v === 'malicious'
            ? 'red' :
          v === 'suspicious'
            ? 'orange' :
          'green';
        return (
          <Tag color={c}>
            {v}
          </Tag>
        );
      }
    },
    {
      title: 'AI Reason',
      dataIndex:
        'ai_reason',
      ellipsis: true
    },
    {
      title: 'Min diff',
      dataIndex:
        'min_diff',
      width: 90,
      render: v =>
        v != null
          ? v + 'm'
          : '-'
    },
    {
      title: 'VPN',
      dataIndex:
        'vpn_count',
      width: 65,
      render: v =>
        v > 0
          ? <Tag
              color="green">
              {v}
            </Tag>
          : '-'
    },
    {
      title: 'AD',
      dataIndex:
        'ad_count',
      width: 65,
      render: v =>
        v > 0
          ? <Tag
              color="geekblue">
              {v}
            </Tag>
          : '-'
    },
    {
      title: 'Last seen',
      dataIndex:
        'last_seen',
      width: 155,
      defaultSortOrder:
        'descend',
      sorter: (a, b) =>
        (a.last_seen || '')
          .localeCompare(
            b.last_seen || ''),
      render: v =>
        fmtTime(v)
    }
  ];

  const detailCols = [
    {
      title: 'Time',
      dataIndex: 'time',
      width: 160,
      render: v =>
        fmtTime(v)
    },
    {
      title: 'Source',
      dataIndex:
        'source',
      width: 80,
      render: v => (
        <Tag color={
          v === 'VPN'
            ? 'green'
            : 'geekblue'
        }>
          {v}
        </Tag>
      )
    },
    {
      title: 'IP',
      dataIndex: 'ip',
      width: 140
    },
    {
      title: 'Geo',
      dataIndex: 'geo',
      width: 170
    },
    {
      title: 'Host',
      dataIndex: 'host'
    }
  ];

  return (
    <Card
      title="Incidents (24h)"
      extra={
        <Space>
          <Input.Search
            placeholder="User"
            allowClear
            style={{
              width: 120
            }}
            onChange={e =>
              setSearch(
                e.target.value)}
          />
          <Select
            value={sevFilter}
            onChange={
              setSevFilter
            }
            style={{
              width: 110
            }}
          >
            <Select.Option
              value="all">
              All
            </Select.Option>
            <Select.Option
              value="high">
              High
            </Select.Option>
            <Select.Option
              value="medium">
              Medium
            </Select.Option>
            <Select.Option
              value="low">
              Low
            </Select.Option>
          </Select>
          <Button
            type="primary"
            icon={
              <BugOutlined />
            }
            loading={busy}
            onClick={analyze}
          >
            AI Triage
          </Button>
          <Button
            icon={
              <DownloadOutlined />
            }
            onClick={
              exportCsv}
          />
          <Button
            icon={
              <ReloadOutlined />
            }
            onClick={load}
          >
            Refresh
          </Button>
        </Space>
      }
    >
      <Table
        dataSource={filtered}
        columns={cols}
        rowKey="username"
        size="small"
        bordered
        pagination={{
          showSizeChanger: true,
          pageSizeOptions: [
            25, 50, 100
          ],
          size: 'small',
          showTotal: t =>
            'Total ' + t
        }}
        expandable={{
          expandedRowRender:
            record => (
              <Table
                dataSource={
                  record
                    .details || []
                }
                columns={
                  detailCols
                }
                rowKey={r =>
                  r.time +
                  '_' +
                  r.source +
                  '_' +
                  r.ip
                }
                pagination={
                  false
                }
                size="small"
              />
            ),
          rowExpandable:
            record =>
              record.details &&
              record
                .details
                .length > 0
        }}
      />
    </Card>
  );
}
