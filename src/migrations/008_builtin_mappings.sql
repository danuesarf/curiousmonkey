-- Mappings that ship with Curious Monkey (CloudTrail event name → IAM action pairs AWS documents),
-- recorded like a reviewer's so stored history is credited the same way.
ALTER TABLE event_action_map DROP CONSTRAINT event_action_map_source_check;
ALTER TABLE event_action_map ADD CONSTRAINT event_action_map_source_check CHECK (source IN ('manual','bedrock','builtin'));
