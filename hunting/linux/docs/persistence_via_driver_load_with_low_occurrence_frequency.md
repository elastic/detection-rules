# Drivers Load with Low Occurrence Frequency

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies drivers loaded with low occurrence frequency on Linux systems. It monitors for the loading of kernel modules (drivers) that have only been seen once across a single host within a year. Such activity can indicate the presence of rare or potentially malicious drivers.

- **UUID:** `e1f59c9a-7a2a-4eb8-a524-97b16a041a4a`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Drivers Load with Low Occurrence Frequency](../queries/persistence_via_driver_load_with_low_occurrence_frequency.toml)

## Query

```sql
from logs-auditd_manager.auditd-*, logs-auditd.log-*, auditbeat-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.category == "driver" and event.action == "loaded-kernel-module" and auditd.data.syscall in ("init_module", "finit_module")
| stats host_count = count_distinct(host.id), total_count = count(*) by auditd.data.name, process.executable, process.name
// Alter this threshold to make sense for your environment
| where host_count == 1 and total_count == 1
| limit 100
| sort auditd.data.name asc
```

## Notes

- Monitors for kernel modules loaded with syscall 'init_module' or 'finit_module', indicating driver load events.
- Counts the occurrence of each driver across all hosts and identifies those seen only once on a single host within the past year.
- Such rare driver loads can indicate potentially malicious activity or the presence of uncommon drivers.

## MITRE ATT&CK Techniques

- [T1547.006](https://attack.mitre.org/techniques/T1547/006)
- [T1069.002](https://attack.mitre.org/techniques/T1069/002)

## License

- `Elastic License v2`
