// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/cilium/cilium/pkg/spanstat"
)

// SpanStat is a statistics structure for storing metrics related to datapath
// load operations.
type SpanStat struct {
	BpfCompilation            spanstat.SpanStat
	BpfWaitForELF             spanstat.SpanStat
	BpfLoadProg               spanstat.SpanStat
	BpfAttachCiliumHost       spanstat.SpanStat
	BpfAttachCiliumNet        spanstat.SpanStat
	BpfAttachNetworkDevices   spanstat.SpanStat
	BpfLoadAndAssign          spanstat.SpanStat
	BpfPolicyMapUpdate        spanstat.SpanStat
	BpfEgressPolicyMapUpdate  spanstat.SpanStat
	BpfRetrieveDevice         spanstat.SpanStat
	BpfAttachSKBProgram       spanstat.SpanStat
	BpfAttachSKBProgramEgress spanstat.SpanStat
	BpfDetachSKBProgramEgress spanstat.SpanStat
	BpfCommit                 spanstat.SpanStat
	BpfEndpointRoute          spanstat.SpanStat
}

// GetMap returns a map of statistic names to stats
func (s *SpanStat) GetMap() map[string]*spanstat.SpanStat {
	return map[string]*spanstat.SpanStat{
		"bpfCompilation":            &s.BpfCompilation,
		"bpfWaitForELF":             &s.BpfWaitForELF,
		"bpfLoadProg":               &s.BpfLoadProg,
		"bpfAttachCiliumHost":       &s.BpfAttachCiliumHost,
		"bpfAttachCiliumNet":        &s.BpfAttachCiliumNet,
		"bpfAttachNetworkDevices":   &s.BpfAttachNetworkDevices,
		"bpfLoadAndAssign":          &s.BpfLoadAndAssign,
		"bpfPolicyMapUpdate":        &s.BpfPolicyMapUpdate,
		"bpfEgressPolicyMapUpdate":  &s.BpfEgressPolicyMapUpdate,
		"bpfRetrieveDevice":         &s.BpfRetrieveDevice,
		"bpfAttachSKBProgram":       &s.BpfAttachSKBProgram,
		"bpfAttachSKBProgramEgress": &s.BpfAttachSKBProgramEgress,
		"bpfDetachSKBProgramEgress": &s.BpfDetachSKBProgramEgress,
		"bpfCommit":                 &s.BpfCommit,
		"bpfEndpointRoute":          &s.BpfEndpointRoute,
	}
}
