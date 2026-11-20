import { CEMEvent, EcsEvent, OcsfEvent } from './types.js';

export class EventNormalizer {
  static toOcsf(ev: CEMEvent): OcsfEvent {
    const lt = String(ev.log_type || 'system').toLowerCase();
    const outcome = String(ev.outcome || 'ok').toLowerCase();
    const isFail = outcome === 'fail' || outcome === 'denied' || outcome === 'error';

    let categoryUid = 1;
    let categoryName = 'System Activity';
    let classUid = 1001;
    let className = 'File System Activity';
    let activityId = 1;
    let activityName = ev.action || 'Other';

    if (lt === 'auth' || lt === 'entra_id' || (lt === 'windows' && (ev.meta?.event_id === 4624 || ev.meta?.event_id === 4625 || ev.meta?.event_id === 4720))) {
      categoryUid = 3;
      categoryName = 'Identity & Access Management';
      classUid = ev.meta?.event_id === 4720 || ev.action?.includes('user_created') ? 3001 : 3002;
      className = classUid === 3001 ? 'Account Change' : 'Authentication';
      activityId = isFail ? 2 : 1;
      activityName = ev.action || (isFail ? 'Logon Failure' : 'Logon');
    } else if (lt === 'web' || lt === 'proxy' || lt === 'canary') {
      categoryUid = 4;
      categoryName = 'Network Activity';
      classUid = 4002;
      className = 'HTTP Activity';
      activityId = 1;
      activityName = lt === 'canary' ? 'Canary Tarpit Probe' : ev.meta?.method ? `HTTP ${ev.meta.method}` : 'HTTP Request';
    } else if (lt === 'dns') {
      categoryUid = 4;
      categoryName = 'Network Activity';
      classUid = 4003;
      className = 'DNS Activity';
      activityId = 1;
      activityName = 'DNS Query';
    } else if (lt === 'firewall' || lt === 'syscollector') {
      categoryUid = 4;
      categoryName = 'Network Activity';
      classUid = 4001;
      className = 'Network Activity';
      activityId = outcome === 'denied' ? 5 : 1;
      activityName = ev.action || 'Traffic';
    } else if (lt === 'cloudtrail' || lt === 'gcp_audit' || lt === 'k8s_audit' || lt === 'mcp_agent') {
      categoryUid = 6;
      categoryName = 'Application Activity';
      classUid = 6003;
      className = lt === 'mcp_agent' ? 'AI Agent Tool API Activity' : 'API Activity';
      activityId = 1;
      activityName = ev.action || 'API Call';
    } else if (lt === 'sysmon' || (lt === 'windows' && ev.meta?.event_id === 4688)) {
      categoryUid = 1;
      categoryName = 'System Activity';
      classUid = 1007;
      className = 'Process Activity';
      activityId = 1;
      activityName = 'Launch';
    } else if (lt === 'fim') {
      categoryUid = 1;
      categoryName = 'System Activity';
      classUid = 1001;
      className = 'File System Activity';
      activityId = ev.action === 'file_deleted' ? 4 : ev.action === 'file_modified' ? 3 : 1;
      activityName = ev.action || 'Modify';
    }

    const sevId = outcome === 'denied' || outcome === 'fail' ? 3 : outcome === 'error' ? 4 : 1;
    const severity = sevId >= 4 ? 'High' : sevId === 3 ? 'Medium' : 'Informational';

    return {
      version: '1.1.0',
      category_uid: categoryUid,
      category_name: categoryName,
      class_uid: classUid,
      class_name: className,
      activity_id: activityId,
      activity_name: activityName,
      severity_id: sevId,
      severity,
      time: Number(ev.ts || Math.floor(Date.now() / 1000)),
      src_endpoint: {
        ip: ev.source_ip || '127.0.0.1',
        hostname: ev.host,
        port: ev.meta?.src_port ? Number(ev.meta.src_port) : undefined,
      },
      dst_endpoint: {
        hostname: ev.meta?.dest_host || ev.host,
        service: ev.meta?.service || ev.log_type,
        path: ev.target,
        port: ev.meta?.dest_port ? Number(ev.meta.dest_port) : undefined,
      },
      actor: {
        user: ev.user ? { name: ev.user } : null,
        process: ev.meta?.process_name || ev.meta?.Image
          ? { name: String(ev.meta.process_name || ev.meta.Image), cmd_line: ev.meta?.CommandLine ? String(ev.meta.CommandLine) : undefined }
          : null,
      },
      status: isFail ? 'Failure' : 'Success',
    };
  }

  static toEcs(ev: CEMEvent): EcsEvent {
    const lt = String(ev.log_type || 'system').toLowerCase();
    const outcome = String(ev.outcome || 'ok').toLowerCase();
    const ecsOutcome: EcsEvent['event.outcome'] =
      outcome === 'ok' ? 'success' : ['fail', 'denied', 'error'].includes(outcome) ? 'failure' : 'unknown';

    let categories: string[] = ['host'];
    if (lt === 'auth' || lt === 'entra_id' || ev.meta?.event_id === 4624 || ev.meta?.event_id === 4625 || ev.meta?.event_id === 4720) {
      categories = ['authentication', 'iam'];
    } else if (lt === 'web' || lt === 'proxy' || lt === 'canary') {
      categories = ['web', 'network'];
    } else if (lt === 'dns' || lt === 'firewall') {
      categories = ['network'];
    } else if (lt === 'cloudtrail' || lt === 'gcp_audit' || lt === 'k8s_audit') {
      categories = ['configuration', 'iam'];
    } else if (lt === 'mcp_agent') {
      categories = ['iam', 'process', 'api'];
    } else if (lt === 'sysmon' || ev.meta?.event_id === 4688) {
      categories = ['process'];
    } else if (lt === 'fim') {
      categories = ['file'];
    }

    const ts = Number(ev.ts || Math.floor(Date.now() / 1000));
    const ecs: EcsEvent = {
      '@timestamp': new Date(ts * 1000).toISOString(),
      'ecs.version': '8.11',
      'event.category': categories,
      'event.action': ev.action,
      'event.outcome': ecsOutcome,
      'event.dataset': `kavalan.${lt}`,
      'source.ip': ev.source_ip || '127.0.0.1',
      'host.name': ev.host || 'unknown',
    };

    if (ev.user) ecs['user.name'] = ev.user;
    if (ev.target && (lt === 'web' || lt === 'proxy' || lt === 'canary')) ecs['url.path'] = ev.target;
    if (ev.meta?.process_name || ev.meta?.Image) ecs['process.name'] = String(ev.meta.process_name || ev.meta.Image);
    if (ev.meta?.CommandLine) ecs['process.command_line'] = String(ev.meta.CommandLine);
    if (ev.meta?.query_name) ecs['dns.question.name'] = String(ev.meta.query_name);
    if (lt === 'cloudtrail') ecs['cloud.provider'] = 'aws';
    else if (lt === 'entra_id') ecs['cloud.provider'] = 'azure';
    else if (lt === 'gcp_audit') ecs['cloud.provider'] = 'gcp';
    else if (lt === 'k8s_audit') ecs['cloud.provider'] = 'kubernetes';
    else if (lt === 'mcp_agent') ecs['cloud.provider'] = 'ai-mcp-gateway';

    return ecs;
  }
}
