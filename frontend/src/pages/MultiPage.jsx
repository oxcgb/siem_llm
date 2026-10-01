import React, {
  useState, useEffect, useMemo
} from 'react';
import {
  Button, Card, Table, Tag,
  Input, Space
} from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import api from '../api';
import { fmtTime, TZ_LABEL } from '../time';

export default function MultiPage() {
  const [data, setData] = useState([]);
  const [search, setSearch] = useState('');

  const load = () =>
    api('/api/multi-logins', { timeout: 60000 })
      .then(d => setData(d?.events || []))
      .catch(() => {});

  useEffect(() => { load(); }, []);

  const filtered = useMemo(() => {
    if (!search) return data;
    const s = search.toLowerCase();
    return data.filter(e =>
      (e.username || '').toLowerCase().includes(s) ||
      (e.ip || '').includes(s));
  }, [data, search]);

  const cols = [
    { title: 'Username', dataIndex: 'username', width: 180 },
    { title: 'IPs', dataIndex: 'total', width: 100,
      render: v => (
        <Tag color={
          v > 5 ? 'red' : v > 2 ? 'orange' : 'blue'
        }>{v}</Tag>
      ) },
    { title: 'Time (' + TZ_LABEL + ')',
      dataIndex: 'time', width: 170,
      render: v => fmtTime(v) },
    { title: 'Source', dataIndex: 'source', width: 90,
      render: v => (
        <Tag color={v === 'VPN' ? 'green' : 'geekblue'}>
          {v}</Tag>
      ) },
    { title: 'IP', dataIndex: 'ip' }
  ];

  return (
    <Card title="Multi-Logins"
      extra={
        <Space>
          <Input.Search placeholder="Search"
            style={{ width: 180 }}
            onChange={e => setSearch(e.target.value)} />
          <Button icon={<ReloadOutlined />}
            onClick={load}>Refresh</Button>
        </Space>
      }>
      <Table
        dataSource={filtered} columns={cols}
        rowKey={r => r.username + r.ip + r.source}
        size="small" bordered
        pagination={{ pageSize: 25 }} />
    </Card>
  );
}