# servicedump
### Tool to investigate mach services and the sandbox

## Usage

I feel usage is better shown with examples.

**List services that a process can open:**

	servicedump <ProcessName|pid> | grep allow

**List services that a process can't open:**

	servicedump <ProcessName|pid> | grep deny

**List process that can open a service:**

	servicedump check <ServiceLabel> | grep allow

**List process that can't open a service:**

	servicedump check <ServiceLabel> | grep deny

**Check if a process can open a service:**

	servicedump check <ServiceLabel> <ProcessName|pid>
