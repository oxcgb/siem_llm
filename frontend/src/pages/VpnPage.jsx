import React, { useState, useEffect } from 'react';
import {
  Button, Card, Table, Tag,
  Descriptions, Input, Select, Space,
  Typography
} from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import api from '../api';
import { fmtTime, TZ_LABEL } from '../time';

const { Text } = Typography;

const HOURS = {
  '1h': 1, '8h': 8, '12h': 12,
  '1d': 24, '7d': 168
};

export default function VpnPage() {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [q, setQ] = useState('');
  const [hours, setHours] = useState('all');

  const load = async (
    p = page, ps = pageSize,
    query = q, h = hours
  ) => {
    const params = new URLSearchParams({
      limit: ps,
      offset: (p - 1) * ps
    });
    if (query) params.set('q', query);
    if (h !== 'all') params.set('hours', HOURS[h]);
    try {
      const d = await api('/api/vpn-events?' + params);
      setEvents(d.events || []);
      setTotal(d.total || 0);
      setPage(p);
      setPageSize(ps);
    } catch (e) { console.error(e); }
  };

  useEffect(() => {
    load(1, 50, '', 'all');
  }, []);

  const cols = [
    { title: 'Time (' + TZ_LABEL + ')',
      dataIndex: 'timestamp', width: 170,
      render: v => fmtTime(v) },
    { title: 'User', dataIndex: 'username' },
    { title: 'Public IP', dataIndex: 'src_ip' },
    { title: 'Internal IP', dataIndex: 'private_ip' },
    { title: 'Action', dataIndex: 'action',
      render: v => (
        <Tag color={
          v === 'login_success' ? 'green' :
          v === 'login_failed' ? 'red' : 'default'
        }>{v}</Tag>
      ) }
  ];

  return (
    <Card title="VPN Events"
      extra={
        <Space>
          <Input.Search placeholder="Search"
            style={{ width: 180 }}
            onSearch={v => {
              setQ(v);
              load(1, pageSize, v, hours);
            }} />
          <Select value={hours}
            onChange={v => {
              setHours(v);
              load(1, pageSize, q, v);
            }} style={{ width: 120 }}>
            <Select.Option value="all">All</Select.Option>
            {Object.keys(HOURS).map(k => (
              <Select.Option key={k} value={k}>
                Last {k}
              </Select.Option>
            ))}
          </Select>
          <Button icon={<ReloadOutlined />}
            onClick={() => load()}>Refresh</Button>
        </Space>
      }>
      <Table
        dataSource={events} columns={cols}
        rowKey="id" size="small"
        pagination={{
          current: page, pageSize: pageSize,
          total: total, showSizeChanger: true,
          onChange: (p, ps) => load(p, ps)
        }}
        expandable={{
          expandedRowRender: r => (
            <Descriptions size="small" column={1} bordered>
              <Descriptions.Item label="Raw">
                <Text code>{r.raw_event || '—'}</Text>
              </Descriptions.Item>
            </Descriptions>
          ),
          rowExpandable: r => !!r.raw_event
        }}
      />
    </Card>
  );
}