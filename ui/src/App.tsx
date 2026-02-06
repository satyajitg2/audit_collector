import { useState, useEffect } from 'react';
import { Layout, Tabs, Table, Form, Input, Button, Card, Tag, Typography, message, Descriptions } from 'antd';
import { FilterOutlined, TableOutlined, DashboardOutlined, ReloadOutlined } from '@ant-design/icons';
import axios from 'axios';
import './App.css';

const { Header, Content } = Layout;
const { Title } = Typography;

interface AuditEvent {
  timestamp: string;
  record_type: number;
  sequence: number;
  fields: Record<string, string>;
}

interface FilterConfig {
  process?: string;
  message?: string;
  subsystem?: string;
  pid?: string;
  thread_id?: string;
  category?: string;
  library?: string;
}

function App() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [form] = Form.useForm();

  // Load initial config
  useEffect(() => {
    axios.get('/api/config').then(res => {
      form.setFieldsValue(res.data);
    });
  }, []);

  // Event Stream (SSE)
  useEffect(() => {
    const eventSource = new EventSource('/api/events');
    eventSource.onmessage = (e) => {
      const newEvent: AuditEvent = JSON.parse(e.data);
      setEvents(prev => [newEvent, ...prev].slice(0, 500)); // Keep last 500
    };
    eventSource.onerror = () => {
      // Retry connection automatically handled by browser usually, but good to know
    };
    return () => {
      eventSource.close();
    };
  }, []);

  const onFinish = async (values: FilterConfig) => {
    setLoading(true);
    try {
      await axios.post('/api/config', values);
      message.success('Filter updated! Collector restarting...');
      setEvents([]); // Clear events on filter change
    } catch (error) {
      message.error('Failed to update config');
    } finally {
      setLoading(false);
    }
  };

  const columns = [
    { title: 'Time', dataIndex: 'timestamp', key: 'timestamp', width: 200, render: (t: string) => new Date(t).toLocaleTimeString() },
    { title: 'Type', dataIndex: 'record_type', key: 'record_type', width: 80 },
    { title: 'Process', key: 'process', render: (_: any, r: AuditEvent) => r.fields['process'] || '-' },
    { title: 'PID', key: 'pid', width: 80, render: (_: any, r: AuditEvent) => r.fields['pid'] || '-' },
    {
      title: 'Message / Details', key: 'msg', render: (_: any, r: AuditEvent) => (
        <div>
          {r.fields['message'] && <div style={{ fontWeight: 500 }}>{r.fields['message']}</div>}
          <div style={{ fontSize: '0.8em', color: '#888' }}>
            {Object.entries(r.fields)
              .filter(([k]) => !['message', 'process', 'pid'].includes(k))
              .map(([k, v]) => <span key={k} style={{ marginRight: 8 }}><Tag>{k}: {v}</Tag></span>)}
          </div>
        </div>
      )
    } // Full raw fields json dump maybe if message empty
  ];

  const items = [
    {
      key: '1',
      label: <span><TableOutlined />Events</span>,
      children: (
        <Table
          dataSource={events}
          columns={columns}
          rowKey={(r) => r.timestamp + r.sequence}
          pagination={{ pageSize: 15 }}
          size="small"
        />
      ),
    },
    {
      key: '2',
      label: <span><FilterOutlined />Filters</span>,
      children: (
        <Card title="Configure Event Filters">
          <Form form={form} layout="vertical" onFinish={onFinish}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <Form.Item name="process" label="Process Name"><Input placeholder="e.g. Code" /></Form.Item>
              <Form.Item name="message" label="Message Contains"><Input placeholder="e.g. error" /></Form.Item>
              <Form.Item name="subsystem" label="Subsystem"><Input /></Form.Item>
              <Form.Item name="category" label="Category"><Input /></Form.Item>
              <Form.Item name="pid" label="PID"><Input placeholder="1234" /></Form.Item>
              <Form.Item name="thread_id" label="Thread ID"><Input /></Form.Item>
              <Form.Item name="library" label="Library / Image Path"><Input /></Form.Item>
            </div>
            <Button type="primary" htmlType="submit" loading={loading} icon={<ReloadOutlined />}>
              Apply Filters & Restart Collector
            </Button>
          </Form>
        </Card>
      ),
    },
    {
      key: '3',
      label: <span><DashboardOutlined />Overview</span>,
      children: (
        <Card>
          <Descriptions title="Product Overview" bordered>
            <Descriptions.Item label="Product">Audit Collector</Descriptions.Item>
            <Descriptions.Item label="Version">0.1.0 (GUI)</Descriptions.Item>
            <Descriptions.Item label="Status">Running</Descriptions.Item>
            <Descriptions.Item label="Port">9357</Descriptions.Item>
            <Descriptions.Item label="Total Captured">{events.length} (Buffer)</Descriptions.Item>
          </Descriptions>
        </Card>
      ),
    },
  ];

  return (
    <Layout className="layout" style={{ minHeight: '100vh' }}>
      <Header style={{ display: 'flex', alignItems: 'center' }}>
        <div className="logo" />
        <Title level={4} style={{ color: 'white', margin: 0 }}>Audit Collector Dashboard</Title>
      </Header>
      <Content style={{ padding: '20px 50px' }}>
        <div className="site-layout-content" style={{ padding: 24, minHeight: 380, background: '#fff' }}>
          <Tabs defaultActiveKey="1" items={items} />
        </div>
      </Content>
    </Layout>
  );
}

export default App;
