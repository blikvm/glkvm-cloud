package device

import "context"

type Repository interface {
	ListAll(ctx context.Context) ([]Device, error)
	ListByDeviceGroupIDs(ctx context.Context, groupIDs []int64) ([]Device, error)
	// ListPaged returns one page of devices (with joined group name) plus the
	// total count of matching rows, doing all filtering/sorting/pagination in SQL.
	ListPaged(ctx context.Context, q ListQuery) ([]ListItem, int64, error)
}
