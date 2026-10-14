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
        self.assertNotIn('raw',response['events'][0])
        self.assertTrue(response['events'][0]['truncated'])
        self.assertLessEqual(len(response['events'][0]['message']),300)

if __name__=='__main__': unittest.main()
