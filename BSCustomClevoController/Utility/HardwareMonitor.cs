using BSCustomClevoController.Controls;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using LibreHardwareMonitor.Hardware;

namespace BSCustomClevoController.Utility
{
    public sealed class HardwareMonitor : IDisposable
    {
        private readonly Computer _computer;
        private readonly object _sync = new object();
        private bool _disposed;

        public HardwareMonitor()
        {
            _computer = new Computer
            {
                IsCpuEnabled = true,
                IsGpuEnabled = true
            };

            _computer.Open();
        }

        public HardwareTelemetry GetTelemetry()
        {
            lock (_sync)
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(HardwareMonitor));

                HardwareTelemetry result = new HardwareTelemetry();

                try
                {
                    UpdateHardware(_computer.Hardware);

                    List<ISensor> cpu = GetSensors(HardwareType.Cpu);

                    List<ISensor> gpu = GetSensors(
                        HardwareType.GpuIntel,
                        HardwareType.GpuNvidia,
                        HardwareType.GpuAmd);

                    result.CpuPower = FindValue(
                        cpu, SensorType.Power, "cpu package", "package");

                    result.CpuTemperature = FindValue(
                        cpu, SensorType.Temperature, "cpu package", "package");

                    result.CpuLoad = FindValue(
                        cpu, SensorType.Load, "total cpu", "cpu total", "total");

                    result.CpuFrequency = GetCpuFrequency(cpu);

                    result.GpuPower = FindValue(
                        gpu, SensorType.Power, "gpu core", "gpu", "chip");

                    result.GpuTemperature = FindValue(
                        gpu, SensorType.Temperature, "gpu core", "core", "hot spot");

                    result.GpuLoad = FindValue(
                        gpu, SensorType.Load, "gpu core", "core", "d3d");

                    result.GpuFrequency = FindValue(
                        gpu, SensorType.Clock, "gpu core", "graphics", "core");
                }
                catch (Exception ex)
                {
                    AppLogger.Log("HardwareMonitor.GetTelemetry", ex);
                }

                return result;
            }
        }

        private List<ISensor> GetSensors(params HardwareType[] types)
        {
            List<ISensor> result = new List<ISensor>();

            CollectSensors(_computer.Hardware, types, result);

            return result;
        }

        private static void CollectSensors(
            IEnumerable<IHardware> hardwareItems,
            HardwareType[] types,
            List<ISensor> destination)
        {
            foreach (IHardware hardware in hardwareItems)
            {
                if (types.Contains(hardware.HardwareType))
                    destination.AddRange(hardware.Sensors);

                CollectSensors(hardware.SubHardware, types, destination);
            }
        }

        private static double? FindValue(
            IEnumerable<ISensor> sensors,
            SensorType type,
            params string[] preferredNames)
        {
            List<ISensor> candidates = sensors
                .Where(s => s.SensorType == type && s.Value.HasValue)
                .ToList();

            foreach (string name in preferredNames)
            {
                ISensor match = candidates.FirstOrDefault(
                    s => s.Name.IndexOf(
                        name, StringComparison.OrdinalIgnoreCase) >= 0);

                if (match != null)
                    return (double)match.Value.Value;
            }

            return candidates.Count == 1
                ? (double?)candidates[0].Value.Value
                : null;
        }

        private static double? GetCpuFrequency(IEnumerable<ISensor> sensors)
        {
            List<ISensor> clocks = sensors
                .Where(s =>
                    s.SensorType == SensorType.Clock &&
                    s.Value.HasValue &&
                    s.Name.IndexOf(
                        "Core", StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();

            if (clocks.Count == 0)
                return FindValue(sensors, SensorType.Clock, "core");

            List<ISensor> effective = clocks
                .Where(s => s.Name.IndexOf(
                    "Effective", StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();

            if (effective.Count > 0)
                clocks = effective;

            return clocks.Average(s => (double)s.Value.Value);
        }

        private static void UpdateHardware(
    IEnumerable<IHardware> hardwareItems)
        {
            foreach (IHardware hardware in hardwareItems)
            {
                hardware.Update();

                // Update nested hardware devices as well.
                UpdateHardware(hardware.SubHardware);
            }
        }

        public string GetSensorReport()
        {
            lock (_sync)
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(HardwareMonitor));

                StringBuilder report = new StringBuilder();

                try
                {
                    UpdateHardware(_computer.Hardware);
                    AppendReport(report, _computer.Hardware);
                }
                catch (Exception ex)
                {
                    AppLogger.Log("HardwareMonitor.GetSensorReport", ex);
                    report.AppendLine(ex.Message);
                }

                return report.ToString();
            }
        }

        private static void AppendReport(
            StringBuilder report,
            IEnumerable<IHardware> hardwareItems)
        {
            foreach (IHardware hardware in hardwareItems)
            {
                report.AppendLine(
                    "[" + hardware.HardwareType + "] " + hardware.Name);

                foreach (ISensor sensor in hardware.Sensors)
                {
                    string value = sensor.Value.HasValue
                        ? sensor.Value.Value.ToString(
                            "0.##", CultureInfo.InvariantCulture)
                        : "N/A";

                    report.AppendLine(
                        "  " + sensor.Name + ": " +
                        value + " " + GetUnit(sensor.SensorType));
                }

                AppendReport(report, hardware.SubHardware);
            }
        }

        private static string GetUnit(SensorType type)
        {
            switch (type)
            {
                case SensorType.Power:
                    return "W";

                case SensorType.Clock:
                    return "MHz";

                case SensorType.Temperature:
                    return "°C";

                case SensorType.Load:
                    return "%";

                default:
                    return type.ToString();
            }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed)
                    return;

                try
                {
                    _computer.Close();
                }
                catch (Exception ex)
                {
                    AppLogger.Log("HardwareMonitor.Dispose", ex);
                }

                _disposed = true;
            }
        }

        private sealed class UpdateVisitor : IVisitor
        {
            public void VisitComputer(IComputer computer)
            {
                computer.Traverse(this);
            }

            public void VisitHardware(IHardware hardware)
            {
                hardware.Update();

                foreach (IHardware subHardware in hardware.SubHardware)
                    subHardware.Accept(this);
            }

            public void VisitSensor(ISensor sensor) { }

            public void VisitParameter(IParameter parameter) { }
        }
    }
}