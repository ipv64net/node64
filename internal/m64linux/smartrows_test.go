package m64linux

import (
	"testing"

	"github.com/ipv64net/node64/internal/m64proto"
)

func smartVal(s m64proto.SMART, key string) (m64proto.SMARTValue, bool) {
	for _, v := range s.Values {
		if v.Key == key {
			return v, true
		}
	}
	return m64proto.SMARTValue{}, false
}

// Alle Werte zum Nachschlagen: ATA liefert die ganze Tabelle, NVMe und SAS benannte Werte (Schluessel wie smartctl -j).
func TestSmartRows(t *testing.T) {
	ata := ParseSmartctl("/dev/sde", readTestdata(t, "smart_ata_failing.json"))
	if len(ata.Attrs) != 4 || len(ata.Values) != 0 {
		t.Fatalf("ATA: %d Attribute, %d Werte", len(ata.Attrs), len(ata.Values))
	}
	if a := ata.Attrs[0]; a.ID != 5 || a.Name != "Reallocate_NAND_Blk_Cnt" || a.Value != 100 || a.Worst != 100 || a.Thresh != 10 || a.Raw != "3" || a.Fail != "" {
		t.Fatalf("Attribut 5: %+v", a)
	}
	if a := ata.Attrs[3]; a.ID != 202 || a.Value != 9 || a.Thresh != 1 || a.Raw != "91" {
		t.Fatalf("Attribut 202: %+v", a)
	}

	nvme := ParseSmartctl("/dev/nvme0n1", []byte(`{"device":{"name":"/dev/nvme0n1","type":"nvme","protocol":"NVMe"},"model_name":"Samsung SSD 980",
		"serial_number":"S64DNX0R1","firmware_version":"3B4QFXO7","smart_status":{"passed":true},
		"nvme_smart_health_information_log":{"critical_warning":4,"temperature":41,"available_spare":100,"available_spare_threshold":10,
		"percentage_used":3,"data_units_read":1000,"data_units_written":2000,"host_reads":5,"host_writes":6,"controller_busy_time":7,
		"power_cycles":87,"power_on_hours":12345,"unsafe_shutdowns":12,"media_errors":1,"num_err_log_entries":2,"warning_temp_time":3,
		"critical_comp_time":0,"temperature_sensors":[41,0,52]}}`))
	if nvme.Firmware != "3B4QFXO7" || len(nvme.Attrs) != 0 {
		t.Fatalf("NVMe: %+v", nvme)
	}
	for key, want := range map[string]m64proto.SMARTValue{
		"critical_warning":     {Value: 4, Unit: "hex"},
		"temperature":          {Value: 41, Unit: "°C"},
		"available_spare":      {Value: 100, Unit: "%"},
		"percentage_used":      {Value: 3, Unit: "%"},
		"data_units_read":      {Value: 512000000, Unit: "B"},
		"data_units_written":   {Value: 1024000000, Unit: "B"},
		"power_on_hours":       {Value: 12345, Unit: "h"},
		"unsafe_shutdowns":     {Value: 12},
		"media_errors":         {Value: 1},
		"critical_comp_time":   {Value: 0, Unit: "min"},
		"temperature_sensor_1": {Value: 41, Unit: "°C"},
		"temperature_sensor_3": {Value: 52, Unit: "°C"},
	} {
		got, ok := smartVal(nvme, key)
		if !ok || got.Value != want.Value || got.Unit != want.Unit {
			t.Errorf("NVMe %s: %+v (vorhanden %v), erwartet %+v", key, got, ok, want)
		}
	}
	if _, ok := smartVal(nvme, "temperature_sensor_2"); ok {
		t.Error("NVMe: Sensor ohne Wert gemeldet")
	}
	// die Auswertung bleibt, wie sie war
	if nvme.CriticalWarning == nil || *nvme.CriticalWarning != 4 || *nvme.WearPercentUsed != 3 || *nvme.TempC != 41 {
		t.Fatalf("NVMe ausgewertet: %+v", nvme)
	}

	sas := ParseSmartctl("/dev/sdc", readTestdata(t, "smart_scsi_sas.json"))
	if sas.Firmware != "GS0F" || len(sas.Attrs) != 0 {
		t.Fatalf("SAS: %+v", sas)
	}
	for key, want := range map[string]float64{"temperature": 38, "drive_trip_temperature": 68, "power_on_hours": 45678, "grown_defects": 12,
		"read_corrected": 123, "read_uncorrected": 1, "write_corrected": 0, "write_uncorrected": 2} {
		if got, ok := smartVal(sas, key); !ok || got.Value != want {
			t.Errorf("SAS %s: %+v (vorhanden %v), erwartet %v", key, got, ok, want)
		}
	}

	// VM ohne SMART: keine erfundene Temperatur
	vm := ParseSmartctl("/dev/sda", section(t, "script_debian12_vm.txt", "smart:/dev/sda"))
	if len(vm.Attrs) != 0 || len(vm.Values) != 0 {
		t.Fatalf("VM: %+v", vm)
	}

	// Begrenzung: nicht beliebig viele Zeilen
	big := []byte(`{"device":{"name":"/dev/sdz","protocol":"ATA"},"ata_smart_attributes":{"table":[`)
	for i := 1; i <= 200; i++ {
		if i > 1 {
			big = append(big, ',')
		}
		big = append(big, []byte(`{"id":1,"name":"x","value":1,"worst":1,"thresh":0,"when_failed":"past","raw":{"value":7,"string":""}}`)...)
	}
	big = append(big, []byte(`]}}`)...)
	many := ParseSmartctl("/dev/sdz", big)
	if len(many.Attrs) != m64proto.MaxSmartRows || many.Attrs[0].Fail != "past" || many.Attrs[0].Raw != "7" {
		t.Fatalf("Begrenzung: %d Attribute, erstes %+v", len(many.Attrs), many.Attrs[0])
	}
}
