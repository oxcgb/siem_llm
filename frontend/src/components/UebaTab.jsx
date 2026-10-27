import React, { useState, useEffect } from 'react';
import {
  Alert, Button, Card, Descriptions, Form, InputNumber,
  Popconfirm, Space, Switch, Tag, Typography, message
} from 'antd';
import api from '../api';

const { Text } = Typography;

// Knob registry: name -> { label, extra, min, max, step, precision }
const KNOBS = [
  {
    name: 'min_days', label: 'Personal baseline: min active days',
    extra: 'Fewer active days in history - the user is scored against ' +
           'the peer profile of established colleagues instead',
    min: 1, max: 30
  },
  {
    name: 'hour_min_occ', label: 'Off-hours: min hour occurrences',
    extra: 'How many times the user must have logged in at the same ' +
           'hour (±1h) for night/evening work to count as personal routine',
    min: 1, max: 24
  },
  {
    name: 'org_hour_min_users', label: 'Peer fallback: min colleagues at hour',
    extra: 'Min established users active at the same hour (±1h) to ' +
           'vouch for a cold-start user',
    min: 1, max: 100
  },
  {
    name: 'fail_mult', label: 'Failed logins: personal median ×',
    extra: 'Typing-retry noise is suppressed while failed count <= ' +
           'personal median × this + margin',
    min: 1, max: 10, step: 0.1, precision: 1
  },
  {
    name: 'fail_margin', label: 'Failed logins: margin',
    extra: 'Additive part of the failed-login personal norm',
    min: 0, max: 100, step: 0.5, precision: 1
  },
  {
    name: 'ad_uncov_min', label: 'AD-without-VPN: routine threshold',
    extra: 'How many uncovered AD logins from public IPs in history ' +
           'before the pattern counts as routine for this user',
    min: 1, max: 100
  },
  {
    name: 'pair_min', label: 'Fast country pair: min occurrences',
    extra: 'How many times the same two countries must flip within ' +
           '2h in history before it counts as commute / mobile geo-flip',
    min: 1, max: 100
  },
  {
    name: 'abs_brute_failed', label: 'Absolute: failed logins in last hour',
    extra: '>= this many failures within the LAST hour plus a ' +
           'successful login = brute-force success (never suppressed)',
    min: 2, max: 1000
  },
  {
    name: 'abs_floor', label: 'Absolute: score floor',
    extra: 'Score floor applied to brute-force success',
    min: 20, max: 100
  },
  {
    name: 'baseline_days', label: 'Baseline training window (days)',
    extra: 'Clamped to RETENTION_DAYS (7 by default) - the engine ' +
           'trains on all kept history',
    min: 1, max: 90
  },
  {
    name: 'ttl_hours', label: 'Baseline refresh interval (hours)',
    extra: 'How often profiles are rebuilt from history',
    min: 1, max: 168
  },
  {
    name: 'instant_min_diff', label: 'Instant VPN->AD handover (minutes)',
    extra: 'VPN login followed by AD activity faster than this is a ' +
           'scripted-access signal (+10 supporting score; never fires alone)',
    min: 0, max: 60, step: 0.5, precision: 1
  }
];

export default function UebaTab() {
  const [form] = Form.useForm();
  const [status, setStatus] = useState(null);
  const [saving, setSaving] = useState(false);
  const [rebuilding, setRebuilding] = useState(false);

  const apply = (d) => {
    setStatus(d);
    if (d?.config) form.setFieldsValue(d.config);
  };

  useEffect(() => {
    api('/api/settings/ueba')
      .then(apply)
      .catch(e => message.error(e.message));
  }, [form]);

  const toggle = async (v) => {
    try {
      apply(await api('/api/settings/ueba', {
        method: 'POST', body: { enabled: v }
      }));
      message.success(v ? 'UEBA enabled' : 'UEBA disabled (v1.5.0 rules)');
    } catch (e) { message.error(e.message); }
  };

  const save = async (v) => {
    setSaving(true);
    try {
      apply(await api('/api/settings/ueba', {
        method: 'POST', body: v
      }));
      message.success('Saved - applied on the next 5-min cycle');
    } catch (e) { message.error(e.message); }
    setSaving(false);
  };

  const reset = async () => {
    try {
      apply(await api('/api/settings/ueba', { method: 'DELETE' }));
      message.success('Reset to defaults');
    } catch (e) { message.error(e.message); }
  };

  const rebuild = async () => {
    setRebuilding(true);
    try {
      const d = await api('/api/settings/ueba/rebuild', { method: 'POST' });
      apply(d);
      if (d.rebuild === 'done') {
        message.success(`Baselines rebuilt: ${d.baselines.users} users`);
      } else {
        message.warning('Skipped (UEBA disabled or a rebuild is running)');
      }
    } catch (e) { message.error(e.message); }
    setRebuilding(false);
  };

  const overrides = Object.keys(status?.overrides || {});

  return (
    <Card title="UEBA" size="small" style={{ maxWidth: 800 }}>
      {status?.env_forced_off && (
        <Alert type="warning" showIcon style={{ marginBottom: 16 }}
          message="Disabled by environment"
          description="UEBA_ENABLED=false is set for the api service - remove it from docker-compose.yml / .env to use this tab." />
      )}

      {status && (
        <Descriptions bordered column={1} size="small"
          style={{ marginBottom: 20 }}>
          <Descriptions.Item label="Enabled">
            <Space>
              <Switch checked={status.enabled} onChange={toggle} />
              {status.enabled
                ? <Tag color="green">on</Tag>
                : <Tag color="red">off (v1.5.0 rules)</Tag>}
            </Space>
          </Descriptions.Item>
          <Descriptions.Item label="Users profiled">
            {status.baselines.users}
          </Descriptions.Item>
          <Descriptions.Item label="Last baseline rebuild">
            {status.baselines.updated_at || 'never'}
          </Descriptions.Item>
          <Descriptions.Item label="Overrides">
            {overrides.length
              ? overrides.map(k => <Tag key={k} color="blue">{k}</Tag>)
              : <Text type="secondary">none (env / defaults)</Text>}
          </Descriptions.Item>
        </Descriptions>
      )}

      <Form form={form} layout="vertical" onFinish={save}>
        {KNOBS.map(k => (
          <Form.Item key={k.name} name={k.name} label={k.label}
            extra={k.extra}>
            <InputNumber style={{ width: 160 }} min={k.min} max={k.max}
              step={k.step || 1} precision={k.precision || 0} />
          </Form.Item>
        ))}
        <Form.Item>
          <Space>
            <Button type="primary" htmlType="submit" loading={saving}>
              Save
            </Button>
            <Button loading={rebuilding} onClick={rebuild}>
              Rebuild baselines now
            </Button>
            <Popconfirm
              title="Drop all UEBA overrides?"
              onConfirm={reset}>
              <Button danger>Reset to defaults</Button>
            </Popconfirm>
          </Space>
        </Form.Item>
      </Form>
    </Card>
  );
}
