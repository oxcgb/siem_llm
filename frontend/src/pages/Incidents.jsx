import React, {
  useState, useEffect, useMemo
} from 'react';
import {
  Alert, Button, Card, Descriptions, Input,
  Modal, Select, Space, Table, Tag,
  Tooltip, Typography, message
} from 'antd';
import {
  BugOutlined,
  CheckOutlined,
  CloseOutlined,
  DownloadOutlined,
  ReloadOutlined,
  UndoOutlined
} from '@ant-design/icons';
import dayjs from 'dayjs';
import api from '../api';
import { fmtTime } from '../time';

const { Text } = Typography;

// rule names sent to the backend as the triage snapshot (per-rule stats)
function ruleSignals(r) {
  const out = [];
  if (r.off_hours) out.push('off_hours');
  if (r.multi_geo) out.push('multi_geo');
  if (r.ad_without_vpn) out.push('ad_without_vpn');
  if (r.failed_logins) out.push('failed_logins');
  return out;
}

export default function Incidents({ authMode, authUser }) {
  const isAdmin = authMode !== 'ad' || !!authUser?.is_admin;

  const [inc, setInc] = useState([]);
  const [stats, setStats] = useState(null);
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [busy, setBusy] = useState(false);
  const [verdictModal, setVerdictModal] = useState(null);
  const [reason, setReason] = useState('');

  const load = () =>
    api('/api/incidents', { timeout: 60000 })
      .then(d => setInc(d?.incidents || []))
      .catch(() => {});

  const loadStats = () => {
    if (!isAdmin) return;
    api('/api/incidents/triage/stats')
      .then(setStats)
      .catch(() => {});
  };

  useEffect(() => {
    load();
    loadStats();
  }, []);

  const filtered = useMemo(() => {
    let d = inc;
    if (sevFilter !== 'all') {
      d = d.filter(e => e.severity === sevFilter);
    }
    if (search) {
      const s = search.toLowerCase();
      d = d.filter(e =>
        (e.username || '').toLowerCase().includes(s));
    }
    return d;
  }, [inc, search, sevFilter]);

  const analyze = async () => {
    setBusy(true);
    message.loading({ content: 'AI Triage...', key: 'ai', duration: 0 });
    try {
      const names = filtered.map(i => i.username);
      const res = await api('/api/incidents/analyze', {
        method: 'POST',
        body: { usernames: names },
        timeout: 600000
      });
      const map = new Map(inc.map(i => [i.username, i]));
      (res.incidents || []).forEach(a => {
        const prev = map.get(a.username) || {};
        map.set(a.username, { ...prev, ...a });
      });
      setInc([...map.values()]);
      message.success({ content: 'Done', key: 'ai' });
    } catch (e) {
      message.error({
        content: 'Failed: ' + e.message,
        key: 'ai',
        duration: 5
      });
    }
    setBusy(false);
  };

  // ---- analyst triage (admin): tp stays visible, fp closes the day ----
  const askVerdict = (r, status) => {
    setReason('');
    setVerdictModal({ username: r.username, date: r.last_seen?.slice(0, 10), status });
  };

  const sendVerdict = async () => {
    if (!verdictModal) return;
    const { username, date, status } = verdictModal;
    const r = inc.find(i => i.username === username);
    try {
      const st = await api('/api/incidents/triage', {
        method: 'POST',
        body: {
          username, date, status, reason,
          signals: ruleSignals(r || {})
        }
      });
      setVerdictModal(null);
      if (isAdmin) setStats(st);
      message.success(
        status === 'fp'
          ? 'Closed as false positive (this user-day)'
          : 'Confirmed as true positive');
      load();
    } catch (e) { message.error(e.message); }
  };

  const reopen = async (r) => {
    try {
      await api(`/api/incidents/triage?username=${encodeURIComponent(r.username)}` +
        `&date=${encodeURIComponent(r.triage.date)}`, { method: 'DELETE' });
      message.success('Reopened');
      load();
      loadStats();
    } catch (e) { message.error(e.message); }
  };

  const exportCsv = () => {
    if (!filtered.length) {
      return;
    }
    const cols = [
      'username', 'severity', 'risk_score', 'ai_verdict',
      'ai_reason', 'mitre', 'triage', 'last_seen'
    ];
    const head = cols.join(',');
    const lines = filtered.map(r =>
      cols.map(c => {
        let v = r[c];
        if (Array.isArray(v)) v = v.join('; ');
        else if (v && typeof v === 'object') v = v.status || '';
        return '"' + String(v ?? '').replace(/"/g, '""') + '"';
      }).join(','));
    const blob = new Blob(
      [[head, ...lines].join('\n')],
      { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'incidents_' + dayjs().format('YYYYMMDD_HHmm') + '.csv';
    a.click();
  };

  const flags = (r) => {
    const tags = [];
    if (r.off_hours) {
      tags.push(<Tag key="oh" color="volcano">Off-hours</Tag>);
    }
    if (r.multi_geo) {
      tags.push(<Tag key="mg" color="magenta">Multi-geo</Tag>);
    }
    if (r.ad_without_vpn) {
      tags.push(<Tag key="nv" color="gold">AD w/o VPN</Tag>);
    }
    if (r.failed_logins) {
      tags.push(
        <Tag key="fl" color="red">
          {r.failed_logins}
          {' failed'}
        </Tag>
      );
    }
    (r.mitre || []).forEach(m => {
      const id = m.split(' ')[0];
      tags.push(
        <Tooltip key={m} title={m}>
          <Tag color="geekblue" style={{ marginInlineEnd: 4 }}>{id}</Tag>
        </Tooltip>
      );
    });
    (r.watchlists || []).forEach(w => {
      tags.push(
        <Tag key={w} color={w === 'elevated' ? 'red' : 'default'}>
          {w === 'elevated' ? 'elevated watchlist' : w}
        </Tag>
      );
    });
    if (r.ueba?.bonus?.includes('instant_switch')) {
      tags.push(<Tag key="inst" color="purple">Instant VPN-&gt;AD</Tag>);
    }
    if (tags.length) {
      return <Space size={4} wrap>{tags}</Space>;
    }
    return <Text type="secondary">—</Text>;
  };

  const triageCell = (r) => {
    if (r.triage) {
      const isFp = r.triage.status === 'fp';
      return (
        <Space size={4} direction="vertical">
          <Tooltip title={r.triage.reason || 'no reason'}>
            <Tag color={isFp ? 'default' : 'green'}>
              {isFp ? 'closed (FP)' : 'confirmed (TP)'}
            </Tag>
          </Tooltip>
          {isAdmin && (
            <Button size="small" type="link"
              icon={<UndoOutlined />} onClick={() => reopen(r)}>
              reopen
            </Button>
          )}
        </Space>
      );
    }
    if (!isAdmin) return <Text type="secondary">—</Text>;
    return (
      <Space size={4}>
        <Tooltip title="True positive - keep visible, count towards precision">
          <Button size="small" icon={<CheckOutlined />}
            onClick={() => askVerdict(r, 'tp')} />
        </Tooltip>
        <Tooltip title="False positive - close this user-day (stops alerting)">
          <Button size="small" danger icon={<CloseOutlined />}
            onClick={() => askVerdict(r, 'fp')} />
        </Tooltip>
      </Space>
    );
  };

  const cols = [
    {
      title: 'Username',
      dataIndex: 'username',
      width: 150,
      fixed: 'left'
    },
    {
      title: 'Severity',
      dataIndex: 'severity',
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
      width: 240,
      render: flags
    },
    {
      title: 'AI Verdict',
      dataIndex: 'ai_verdict',
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
      dataIndex: 'ai_reason',
      ellipsis: true
    },
    {
      title: 'Triage',
      key: 'triage',
      width: 140,
      render: (v, r) => triageCell(r)
    },
    {
      title: 'Min diff',
      dataIndex: 'min_diff',
      width: 90,
      render: v =>
        v != null
          ? v + 'm'
          : '-'
    },
    {
      title: 'VPN',
      dataIndex: 'vpn_count',
      width: 65,
      render: v =>
        v > 0
          ? <Tag color="green">{v}</Tag>
          : '-'
    },
    {
      title: 'AD',
      dataIndex: 'ad_count',
      width: 65,
      render: v =>
        v > 0
          ? <Tag color="geekblue">{v}</Tag>
          : '-'
    },
    {
      title: 'Last seen',
      dataIndex: 'last_seen',
      width: 155,
      defaultSortOrder: 'descend',
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
      dataIndex: 'source',
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

  const statsBar = () => {
    if (!isAdmin || !stats) return null;
    const { total, precision, per_rule } = stats;
    if (!total.tp && !total.fp) return null;
    return (
      <Alert type="success" showIcon style={{ marginBottom: 12 }}
        message={
          <Space wrap>
            <Text strong>Detection quality:</Text>
            <Tag color="green">TP {total.tp}</Tag>
            <Tag>FP {total.fp}</Tag>
            <Tag color={precision != null && precision < 50 ? 'orange' : 'blue'}>
              precision {precision == null ? '—' : precision + '%'}
            </Tag>
            {Object.entries(per_rule).map(([rule, s]) => (
              <Tooltip key={rule}
                title={`${rule}: ${s.tp} TP / ${s.fp} FP`}>
                <Tag>{rule.split(' ')[0]} {s.tp}/{s.fp}</Tag>
              </Tooltip>
            ))}
          </Space>
        }
      />
    );
  };

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
              setSearch(e.target.value)}
          />
          <Select
            value={sevFilter}
            onChange={setSevFilter}
            style={{
              width: 110
            }}
          >
            <Select.Option value="all">All</Select.Option>
            <Select.Option value="high">High</Select.Option>
            <Select.Option value="medium">Medium</Select.Option>
            <Select.Option value="low">Low</Select.Option>
          </Select>
          <Button
            type="primary"
            icon={<BugOutlined />}
            loading={busy}
            onClick={analyze}
          >
            AI Triage
          </Button>
          <Button
            icon={<DownloadOutlined />}
            onClick={exportCsv}
          />
          <Button
            icon={<ReloadOutlined />}
            onClick={load}
          >
            Refresh
          </Button>
        </Space>
      }
    >
      {statsBar()}
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

      <Modal
        title={verdictModal?.status === 'fp'
          ? `Close ${verdictModal?.username} (${verdictModal?.date}) as FALSE POSITIVE?`
          : `Confirm ${verdictModal?.username} (${verdictModal?.date}) as TRUE POSITIVE?`}
        open={!!verdictModal}
        onOk={sendVerdict}
        onCancel={() => setVerdictModal(null)}
        okText="Apply"
        okButtonProps={{ danger: verdictModal?.status === 'fp' }}
      >
        <p>
          {verdictModal?.status === 'fp'
            ? 'This user-day will drop out of the automatic list and stop alerting. ' +
              'Tomorrow the user is scored fresh (the verdict is per day).'
            : 'The incident stays visible with the verdict attached and counts towards precision.'}
        </p>
        <Input
          placeholder="Reason (optional, shown on hover and in the audit log)"
          value={reason}
          onChange={e => setReason(e.target.value)}
          maxLength={300}
        />
      </Modal>
    </Card>
  );
}
