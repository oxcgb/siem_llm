import React, { useState, useEffect } from 'react';
import {
  Button, Card, Descriptions, Typography
} from 'antd';
import api from '../api';

const { Title, Paragraph } = Typography;

export default function About() {
  const [golden, setGolden] = useState(null);
  const [version, setVersion] = useState('1.5.0');
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    api('/api/config', { auth: false })
      .then(c => { if (c.version) setVersion(c.version); })
      .catch(() => {});
  }, []);

  const checkGolden = async () => {
    setChecking(true);
    setGolden(null);
    try {
      setGolden(await api('/api/golden-status'));
    } catch (e) {
      setGolden({ ok: false, error: e.message });
    }
    setChecking(false);
  };

  return (
    <Card title="About" style={{ maxWidth: 900 }}>
      <Title level={3}>SOC LLM Analyzer</Title>
      <Paragraph>Automated SOC analyst.</Paragraph>
      <Descriptions title="System" bordered
        column={1} size="small">
        <Descriptions.Item label="Version">{version}</Descriptions.Item>
      </Descriptions>
      <Descriptions title="Backend" bordered
        column={1} size="small"
        style={{ marginTop: 16 }}>
        <Descriptions.Item label="Framework">
          FastAPI + Uvicorn</Descriptions.Item>
        <Descriptions.Item label="Database">
          SQLite (WAL) + daily backup</Descriptions.Item>
        <Descriptions.Item label="Scheduler">
          APScheduler</Descriptions.Item>
        <Descriptions.Item label="Alerting">
          Telegram (proxy via TG_PROXY)</Descriptions.Item>
        <Descriptions.Item label="Audit">
          SQLite audit_log + cleanup cron</Descriptions.Item>
      </Descriptions>
      <Descriptions title="LLM Engine" bordered
        column={1} size="small"
        style={{ marginTop: 16 }}>
        <Descriptions.Item label="Engine">
          vLLM v0.11.0</Descriptions.Item>
        <Descriptions.Item label="Model">
          Qwen3-8B-AWQ</Descriptions.Item>
        <Descriptions.Item label="Thinking">
          disabled (enable_thinking=false)</Descriptions.Item>
        <Descriptions.Item label="Output">
          JSON schema / guided</Descriptions.Item>
        <Descriptions.Item label="Temperature">
          0.0</Descriptions.Item>
      </Descriptions>
      <Descriptions title="Quality" bordered
        column={1} size="small"
        style={{ marginTop: 16 }}>
        <Descriptions.Item label="Golden Test">
          <Button size="small" loading={checking}
            onClick={checkGolden}>Run now</Button>
          {golden && (
            <span style={{ marginLeft: 12 }}>
              {golden.ok
                ? (golden.score || '?')
                : ('error: ' + (golden.error || '?'))}
            </span>
          )}
        </Descriptions.Item>
        <Descriptions.Item label="Unit tests">
          pytest (normalizer, scoring, alerts, LLM 400s)</Descriptions.Item>
      </Descriptions>
      <Descriptions title="Security" bordered
        column={1} size="small"
        style={{ marginTop: 16 }}>
        <Descriptions.Item label="Auth">
          AD (LDAP) + Local</Descriptions.Item>
        <Descriptions.Item label="SSRF">
          resolve-once, IP pinned</Descriptions.Item>
        <Descriptions.Item label="Sessions">
          Bearer + TTL, admin-gated endpoints</Descriptions.Item>
        <Descriptions.Item label="Alerts">
          Telegram (dedup + cooldown)</Descriptions.Item>
      </Descriptions>
    </Card>
  );
}