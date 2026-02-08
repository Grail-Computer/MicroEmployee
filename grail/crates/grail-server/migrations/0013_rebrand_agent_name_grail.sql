-- Rebrand the default agent name back to "Grail".
-- Keep existing custom names as-is.
UPDATE settings
SET agent_name = 'Grail'
WHERE agent_name IN ('MicroEmployee', 'μEmployee');

