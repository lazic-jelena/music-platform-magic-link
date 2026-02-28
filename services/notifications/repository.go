package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gocql/gocql"
)

type Notification struct {
	UserID         string    `json:"user_id"`
	NotificationID string    `json:"notification_id"`
	Type           string    `json:"type"`
	Message        string    `json:"message"`
	CreatedAt      time.Time `json:"created_at"`
}

type NotificationRepository struct {
	session *gocql.Session
}

func NewNotificationRepository(cfg Config) (*NotificationRepository, error) {
	host := cfg.CassandraHost
	if host == "" {
		host = "cassandra"
	}

	port := 9042
	if cfg.CassandraPort != "" {
		if p, err := strconv.Atoi(cfg.CassandraPort); err == nil {
			port = p
		}
	}

	// 1) Connect to "system" keyspace to ensure schema exists
	sysCluster := gocql.NewCluster(host)
	sysCluster.Port = port
	sysCluster.Keyspace = "system"
	sysCluster.Consistency = gocql.Quorum
	sysCluster.ConnectTimeout = 8 * time.Second
	sysCluster.Timeout = 8 * time.Second

	var sysSession *gocql.Session
	var err error

	for i := 1; i <= 10; i++ {
		sysSession, err = sysCluster.CreateSession()
		if err == nil {
			break
		}
		fmt.Printf("Cassandra not ready (system session) attempt %d/10: %v\n", i, err)
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Cassandra (system keyspace): %w", err)
	}
	defer sysSession.Close()

	if err := ensureSchema(sysSession); err != nil {
		return nil, fmt.Errorf("failed to ensure schema: %w", err)
	}

	// 2) Now connect to notifications keyspace
	notifCluster := gocql.NewCluster(host)
	notifCluster.Port = port
	notifCluster.Keyspace = "notifications"
	notifCluster.Consistency = gocql.Quorum
	notifCluster.ConnectTimeout = 8 * time.Second
	notifCluster.Timeout = 8 * time.Second

	var session *gocql.Session
	for i := 1; i <= 10; i++ {
		session, err = notifCluster.CreateSession()
		if err == nil {
			fmt.Println("Connected to Cassandra (notifications keyspace)")
			return &NotificationRepository{session: session}, nil
		}
		fmt.Printf("Cassandra not ready (notifications session) attempt %d/10: %v\n", i, err)
		time.Sleep(3 * time.Second)
	}

	return nil, fmt.Errorf("failed to connect to Cassandra (notifications keyspace): %w", err)
}

func ensureSchema(s *gocql.Session) error {
	// Create keyspace
	if err := s.Query(`
		CREATE KEYSPACE IF NOT EXISTS notifications
		WITH replication = {
		  'class': 'SimpleStrategy',
		  'replication_factor': 1
		};
	`).Exec(); err != nil {
		return err
	}

	// Create table (fully qualified)
	if err := s.Query(`
		CREATE TABLE IF NOT EXISTS notifications.notifications_by_user (
			user_id TEXT,
			created_at TIMESTAMP,
			notification_id TEXT,
			type TEXT,
			message TEXT,
			PRIMARY KEY ((user_id), created_at, notification_id)
		) WITH CLUSTERING ORDER BY (created_at DESC);
	`).Exec(); err != nil {
		return err
	}

	return nil
}

func (r *NotificationRepository) GetByUser(userID string) ([]Notification, error) {
	iter := r.session.Query(`
		SELECT user_id, notification_id, type, message, created_at
		FROM notifications_by_user
		WHERE user_id = ?
	`, userID).Iter()

	var notifications []Notification
	var n Notification

	for iter.Scan(&n.UserID, &n.NotificationID, &n.Type, &n.Message, &n.CreatedAt) {
		notifications = append(notifications, n)
	}

	if err := iter.Close(); err != nil {
		return nil, err
	}

	return notifications, nil
}
