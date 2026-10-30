"""Self test for zwift_video_monitor: builds a synthetic pcap and checks the analysis."""
import os, subprocess, sys, tempfile, json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import zwift_video_monitor as m  # noqa: E402


def main():
    tmp = tempfile.mkdtemp()
    pcap = os.path.join(tmp, 'test.pcap')
    subprocess.check_call([sys.executable, '-I', os.path.join(HERE, '_make_test_pcap.py'), pcap])
    log = m.Log()
    cap, hosts, flows = m.analyse_captures([pcap], {'192.168.1.50'}, None, None, log)
    by_ip = {h['ip']: h for h in hosts}
    assert cap['packets'] == 106, cap['packets']
    assert by_ip['23.1.2.3']['bytes_in'] == 150000, by_ip['23.1.2.3']
    assert 'video.zwift.com' in by_ip['23.1.2.3']['names']
    assert 'zwift.akamaized.net' in by_ip['23.1.2.3']['names']
    assert by_ip['1.2.3.4']['names'] == ['cdn.zwift.com']
    assert by_ip['5.6.7.8']['quic'] is True
    assert cap['dns_queries'] == {'video.zwift.com': 1}
    assert cap['http_requests'][0]['request'].startswith('GET /gameassets/x.m3u8')
    assert any('mpegurl' in ct for f in flows for ct in f['http_content_types'])
    report = m.build_text_report({'capture': cap, 'hosts': hosts, 'process_data': {}, 'file_changes': [], 'system_info': {}})
    assert 'video.zwift.com' in report
    print('selftest OK')


if __name__ == '__main__':
    main()
