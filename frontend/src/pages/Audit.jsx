import React, { useState, useEffect } from 'react';
import {
  Button, Card, Input, Table, Tag,
  Space, message
} from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import api from '../api';
import { fmtTime } from '../time';

export default function Audit() {
  const [entries, setEntries] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [search, setSearch] = useState('');

  const load = async (
    p = page, ps = pageSize, q = search
  ) => {
    const params = new URLSearchParams({
      limit: ps,
      offset: (p - 1) * ps
    });
    if (q) params.set('username', q);
    try {
      const d = await api('/api/audit?' + params);
      setEntries(d.entries || []);
      setTotal(d.total || 0);
      setPage(p);
      setPageSize(ps);
    } catch (e) { message.error(e.message); }
  };

  useEffect(() => { load(1, 50, ''); }, []);

  const actionColor = {
    'login': 'green', 'logout': 'default',
    'ds_add': 'blue', 'ds_update': 'blue',
    'ds_delete': 'red', 'clear_vpn': 'red',
    'clear_ad': 'red', 'cleanup': 'orange',
    'prompt_update': 'purple',
    'telegram_update': 'purple',
    'triage': 'cyan', 'fetch': 'cyan',
    'ldap_update': 'blue',
    'rule_add': 'blue', 'rule_update': 'blue',
    'rule_delete': 'red', 'ttl_update': 'purple',
    'audit_cleanup': 'orange', 'triage_toggle': 'orange'
  };

  const cols = [
    { title: 'Time (UTC)', dataIndex: 'timestamp',
      width: 170, render: v => fmtTime(v) },
    { title: 'User', dataIndex: 'username', width: 140 },
    { title: 'Action', dataIndex: 'action', width: 140,
      render: v => (
        <Tag color={actionColor[v] || 'default'}>
          {v}</Tag>
      ) },
    { title: 'Target', dataIndex: 'target', ellipsis: true },
    { title: 'Details', dataIndex: 'details', ellipsis: true }
  ];

  return (
    <Card title="Audit Log"
      extra={
        <Space>
          <Input.Search placeholder="User"
            allowClear style={{ width: 150 }}
            onSearch={v => {
              setSearch(v);
              load(1, pageSize, v);
            }} />
          <Button icon={<ReloadOutlined />}
            onClick={() => load()}>Refresh</Button>
        </Space>
      }>
      <Table
        dataSource={entries} columns={cols}
        rowKey="id" size="small"
        pagination={{
          current: page, pageSize: pageSize,
          total: total, showSizeChanger: true,
          onChange: (p, ps) => load(p, ps)
        }} /></Card>
  );
}