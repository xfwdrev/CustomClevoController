using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BSCustomClevoController.Controls
{
    public struct HardwareTelemetry
    {
        public double? CpuPower { get; set; }
        public double? CpuFrequency { get; set; }
        public double? CpuTemperature { get; set; }
        public double? CpuLoad { get; set; }

        public double? GpuPower { get; set; }
        public double? GpuFrequency { get; set; }
        public double? GpuTemperature { get; set; }
        public double? GpuLoad { get; set; }
    }
}
