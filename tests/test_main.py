import unittest
import asyncio
from unittest.mock import AsyncMock, patch
import main

class InvestigatorTests(unittest.TestCase):
    def entry(self, message, level='ERROR'):
        return main.parse_entry('1791887394971000000', f'2026-10-13 10:29:54.971 [worker-1] {level} [pH8NUNKM,super_admin] [123] --- x.y.Logger : {message}')
    def test_exception(self):
        entry=self.entry('User got a com.foo.ProgramException while accessing /x\ncom.foo.ProgramException: Invalid Status response from KaleidoFIN\n\tat Foo.java:803')
        self.assertEqual(entry['exception'],'com.foo.ProgramException')
        event, exception=main.request_event(entry,'pH8NUNKM',1)
        self.assertEqual(event['eventType'],'EXCEPTION')
        self.assertEqual(exception['message'],'Invalid Status response from KaleidoFIN')
        self.assertEqual(exception['stackTrace'],entry['message'])
    def test_advice_prefixed_exception(self):
        message='GlobalExceptionHandlingControllerAdvice: com.sensei.dcborigination.exception.ProgramException: Invalid Status response from KaleidoFIN\n\tat Foo.java:803'
        entry=self.entry(message)
        event, exception=main.request_event(entry,'pH8NUNKM',1)
        self.assertEqual(entry['exception'],'com.sensei.dcborigination.exception.ProgramException')
        self.assertEqual(event['eventType'],'EXCEPTION')
        self.assertEqual(exception['message'],'Invalid Status response from KaleidoFIN')
        self.assertEqual(exception['stackTrace'],message)
    def test_casual_mention(self):
        entry=self.entry('Caught ProgramException and recovered','INFO')
        self.assertIsNone(entry['exception'])
    def test_timestamp(self):
        entry=self.entry('hello','INFO')
        self.assertTrue(entry['timestamp'].endswith('+00:00'))
        self.assertEqual(entry['applicationTimestamp'],'2026-10-13 10:29:54.971')
        self.assertEqual(entry['timestamp'],'2026-10-13T10:29:54.971000+00:00')
    def test_end_fallback(self):
        entry=self.entry('REQ END | method=POST | uri=/api/test | status=500 | duration=20ms','INFO')
        result=main.build_user_activity([entry],'super_admin',100)
        self.assertEqual(result['requests'][0]['method'],'POST')
        self.assertEqual(result['requests'][0]['uri'],'/api/test')
    def test_redaction(self):
        self.assertNotIn('1234567890',main.redact_sensitive_text('{"mobileNo":"1234567890"}'))
    def test_request_event_keeps_large_log_preview_safe(self):
        message='{"payload":"' + ('x' * 450) + '","mobileNo":"1234567890"}'
        entry=self.entry(message,'INFO')
        entry=main.redact_request_entry(entry)
        event, exception=main.request_event(entry,'pH8NUNKM',1)
        self.assertIsNone(exception)
        self.assertEqual(event['eventType'],'APPLICATION_LOG')
        self.assertLessEqual(len(event['message']),300)
        self.assertTrue(event['truncated'])
        self.assertNotIn('1234567890',event['message'])
    def test_request_timeline_keeps_legacy_fields_and_safe_structured_events(self):
        entry=self.entry('{"mobileNo":"1234567890","payload":"' + ('x' * 400) + '"}','INFO')
        with patch('main.loki_query',new=AsyncMock(return_value=[entry])):
            response=asyncio.run(main.request_timeline('pH8NUNKM'))
        self.assertTrue({'request_id','environment','count','truncated_possible','start','end','errors','timeline'} <= response.keys())
        self.assertIn('raw',response['timeline'][0])
        self.assertNotIn('1234567890',response['timeline'][0]['raw'])
        self.assertEqual(response['events'][0]['raw'],response['timeline'][0]['raw'])
        self.assertTrue(response['events'][0]['truncated'])
        self.assertLessEqual(len(response['events'][0]['message']),300)
    def test_analysis_context_redacts_sensitive_data_and_reduces_noise(self):
        text = ('DEBUG routine detail\n'
                'REQ START | method=POST | uri=/api/test\n'
                'Authorization: Bearer secret-token-value\n'
                'authorization: AWS4-HMAC-SHA256 Credential=private&Signature=hidden\n'
                'mobile=9876543210 email=user@example.com\n'
                'ERROR external API failed status=502\n'
                'com.example.ServiceException: request failed\n'
                '\tat com.example.Service.call(Service.java:42)\n'
                '\tat com.example.Service.call(Service.java:42)\n'
                'webhook payload: ' + ('x' * 800))
        context, indices = main.build_analysis_context(text=text)
        self.assertNotIn('secret-token-value', context)
        self.assertNotIn('Signature=hidden', context)
        self.assertNotIn('9876543210', context)
        self.assertNotIn('user@example.com', context)
        self.assertNotIn('DEBUG routine detail', context)
        self.assertNotIn('x' * 100, context)
        self.assertEqual(indices, set())
        self.assertIn('[MOBILE]', context)
        self.assertIn('Service.java:42', context)
        payload_context, _ = main.build_analysis_context(
            text='webhook payload status=502 error=upstream down requestBody=' + ('x' * 800)
        )
        self.assertIn('status=502', payload_context)
        self.assertNotIn('x' * 100, payload_context)
    def test_analysis_stack_keeps_deepest_cause_and_application_frames(self):
        stack = ('com.sensei.RequestException: request failed\n'
                 '\tat com.sensei.RequestService.handle(RequestService.java:20)\n'
                 '\tat org.springframework.web.Filter.doFilter(Filter.java:10)\n'
                 'Caused by: com.vendor.WrapperException: wrapper failed\n'
                 '\tat com.vendor.Client.call(Client.java:30)\n'
                 'Caused by: java.net.SocketTimeoutException: Read timed out\n'
                 '\tat java.base/sun.nio.Socket.read(Socket.java:40)\n'
                 '\tat java.base/sun.nio.Socket.read(Socket.java:40)')
        result = main._truncate_stack(stack)
        self.assertIn('com.sensei.RequestException: request failed', result)
        self.assertIn('Caused by: java.net.SocketTimeoutException: Read timed out', result)
        self.assertIn('RequestService.java:20', result)
        self.assertEqual(result.count('Socket.read(Socket.java:40)'), 1)
        self.assertLessEqual(result.count('at org.springframework'), 1)
        capped = main._truncate_stack(stack, 100)
        self.assertLessEqual(len(capped), 100)
        self.assertIn('SocketTimeoutException', capped)
    def test_analysis_context_keeps_late_failure_with_event_budget(self):
        events = [{'eventId': f'event-{index}', 'level': 'INFO', 'message': f'Routine event {index}'}
                  for index in range(1, 46)]
        events[0]['message'] = 'REQ START | method=POST | uri=/api/test'
        events[-1]['message'] = 'REQ END | method=POST | uri=/api/test | status=500'
        events.append({'eventId': 'event-46', 'level': 'ERROR', 'message': 'Late failure after retries'})
        investigation = {'request': {'requestId': 'test1234'}, 'events': events, 'exceptions': []}
        context, indices = main.build_analysis_context(investigation=investigation)
        parsed = __import__('json').loads(context)
        self.assertLessEqual(len(parsed['events']), main.ANALYSIS_MAX_EVENTS)
        self.assertIn(46, indices)
        self.assertEqual([item['eventIndex'] for item in parsed['events']],
                         sorted(item['eventIndex'] for item in parsed['events']))
        self.assertIn(1, indices)
        self.assertIn(45, indices)
    def test_payload_filter_keeps_only_business_failure_facts(self):
        huge_response = ('getLoanStatus response: {"errorCode":"ER021",'
                         '"message":"Loan status lookup rejected","payload":"' + ('x' * 1200) + '"}')
        reduced = main._reduce_payload_noise(huge_response)
        self.assertIn('ER021', reduced)
        self.assertIn('Loan status lookup rejected', reduced)
        self.assertNotIn('x' * 100, reduced)
        self.assertIsNone(main._reduce_payload_noise('webhook payload: ' + ('x' * 1200)))
    def test_analysis_context_keeps_normal_request_without_errors(self):
        context, indices = main.build_analysis_context(
            text='REQ START | method=GET | uri=/api/status\nINFO request completed normally\n'
                 'REQ END | method=GET | uri=/api/status | status=200')
        self.assertIn('request completed normally', context)
        self.assertEqual(indices, set())
        self.assertNotIn('ERROR', context)
    def test_analysis_redacts_sensitive_values_and_auth_headers(self):
        source = ('Authorization: Bearer secret-value\n'
                  'Cookie: SESSION=secret-session; other=secret-cookie\n'
              'cookie=SESSION=inline-session; other=inline-cookie\n'
                  'pan=ABCDE1234F aadhaar=1234 5678 9012 mobile=9876543210 '
                  'email=person@example.com')
        result = main.redact_analysis_text(source)
        for sensitive in ('secret-value', 'secret-session', 'secret-cookie', 'inline-session',
                  'inline-cookie', 'ABCDE1234F',
                          '1234 5678 9012', '9876543210', 'person@example.com'):
            self.assertNotIn(sensitive, result)
    def test_analysis_item_normalization_only_removes_real_list_prefixes(self):
        normalized = main.normalize_analysis_items([
            '1. Check service mapping\n2) "Verify downstream status"',
            '- Preserve -value exactly\n\u2022 Check request completion',
            '3.14 release behavior\n"Quoted item"\n   ',
        ])
        self.assertEqual(normalized, [
            'Check service mapping', 'Verify downstream status',
            'Preserve -value exactly', 'Check request completion',
            '3.14 release behavior', 'Quoted item',
        ])
    def test_analysis_prompt_sets_evidence_and_http_constraints(self):
        instructions = ' '.join(main.ANALYSIS_SYSTEM_INSTRUCTIONS.split())
        self.assertIn('An "not found" lookup does not prove a database record is missing', instructions)
        self.assertIn('HTTP 200 does not prove every internal operation succeeded', instructions)
        self.assertIn('An ERROR log alone does not prove the overall request failed', instructions)
        self.assertIn('HIGH requires strong, direct evidence', instructions)
        self.assertIn('Reference only supplied event indices', instructions)
    def test_analysis_rejects_conflicting_inputs_without_groq_call(self):
        with (
            patch.dict('os.environ', {'API_TOKEN': 'test-token'}),
            patch('main.call_groq', new=AsyncMock()) as groq,
        ):
            with self.assertRaises(main.HTTPException) as raised:
                asyncio.run(main.analyze_request(main.AnalyzeRequest(requestId='pH8NUNKM', text='log')))
        self.assertEqual(raised.exception.status_code, 400)
        groq.assert_not_awaited()
    def test_analysis_request_id_cache_uses_fingerprint(self):
        investigation = {
            'count': 2,
            'request': {'requestId': 'pH8NUNKM', 'method': 'POST', 'uri': '/api/test', 'status': 500},
            'events': [
                {'eventId': 'event-1', 'timestamp': '2026-10-13T10:29:54Z', 'level': 'INFO',
                 'logger': 'sample.Controller', 'message': 'REQ START | method=POST | uri=/api/test'},
                {'eventId': 'event-2', 'timestamp': '2026-10-13T10:29:55Z', 'level': 'ERROR',
                 'logger': 'sample.Service', 'message': 'External API failed status=502'},
            ],
            'exceptions': [],
        }
        response = {
            'summary': 'External call failed', 'likelyCause': 'The upstream returned HTTP 502',
            'confidence': 'medium', 'evidence': [{'eventIndex': 2, 'description': 'Upstream status 502'}],
            'suggestedChecks': ['Inspect upstream availability'], 'limitations': [],
            'model': main.GROQ_MODEL,
        }
        main.ANALYSIS_CACHE.clear()
        with (
            patch.dict('os.environ', {'API_TOKEN': 'test-token'}),
            patch('main.request_timeline', new=AsyncMock(return_value=investigation)),
            patch('main.call_groq', new=AsyncMock(return_value=response)) as groq,
        ):
            first = asyncio.run(main.analyze_request(main.AnalyzeRequest(requestId='pH8NUNKM')))
            second = asyncio.run(main.analyze_request(main.AnalyzeRequest(requestId='pH8NUNKM')))
        self.assertEqual(first, second)
        groq.assert_awaited_once()
        self.assertEqual(first['evidence'][0]['eventIndex'], 2)
        main.ANALYSIS_CACHE.clear()

if __name__=='__main__': unittest.main()
