package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3Storage is a storage backed by AWS S3
type S3Storage struct {
	Storage
	bucket      string
	s3          *s3.Client
	uploader    *manager.Uploader
	logger      *log.Logger
	purgeDays   time.Duration
	noMultipart bool
}

// NewS3Storage is the factory for S3Storage
func NewS3Storage(ctx context.Context, accessKey, secretKey, bucketName string, purgeDays int, region, endpoint string, disableMultipart bool, forcePathStyle bool, logger *log.Logger) (*S3Storage, error) {
	cfg, err := getAwsConfig(ctx, accessKey, secretKey)
	if err != nil {
		return nil, err
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.Region = region
		o.UsePathStyle = forcePathStyle
		if len(endpoint) > 0 {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})

	return &S3Storage{
		bucket: bucketName,
		s3:     client,
		uploader: manager.NewUploader(client, func(u *manager.Uploader) {
			if !disableMultipart {
				u.Concurrency = 20
			} else {
				u.Concurrency = 1
			}
			u.LeavePartsOnError = false
		}),
		logger:      logger,
		noMultipart: disableMultipart,
		purgeDays:   time.Duration(purgeDays*24) * time.Hour,
	}, nil
}

// Type returns the storage type
func (s *S3Storage) Type() string {
	return "s3"
}

// Head retrieves content length of a file from storage
func (s *S3Storage) Head(ctx context.Context, token string, filename string) (contentLength uint64, err error) {
	key := fmt.Sprintf("%s/%s", token, filename)

	headRequest := &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}

	// content type , content length
	response, err := s.s3.HeadObject(ctx, headRequest)
	if err != nil {
		return
	}

	if response.ContentLength != nil {
		contentLength = uint64(*response.ContentLength)
	}

	return
}

// Purge cleans up the storage
func (s *S3Storage) Purge(context.Context, time.Duration) (err error) {
	// NOOP expiration is set at upload time
	return nil
}

// IsNotExist indicates if a file doesn't exist on storage
func (s *S3Storage) IsNotExist(err error) bool {
	if err == nil {
		return false
	}

	var nkerr *types.NoSuchKey
	if errors.As(err, &nkerr) {
		return true
	}

	var notFound *types.NotFound
	return errors.As(err, &notFound)
}

// Get retrieves a file from storage
func (s *S3Storage) Get(ctx context.Context, token string, filename string, rng *Range) (reader io.ReadCloser, contentLength uint64, err error) {
	key := fmt.Sprintf("%s/%s", token, filename)

	getRequest := &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}

	if rng != nil {
		getRequest.Range = aws.String(rng.Range())
	}

	response, err := s.s3.GetObject(ctx, getRequest)
	if err != nil {
		return
	}

	if response.ContentLength != nil {
		contentLength = uint64(*response.ContentLength)
	}
	if rng != nil && response.ContentRange != nil {
		rng.SetContentRange(*response.ContentRange)
	}

	reader = response.Body
	return
}

// Delete removes a file from storage
func (s *S3Storage) Delete(ctx context.Context, token string, filename string) (err error) {
	metadata := fmt.Sprintf("%s/%s.metadata", token, filename)
	deleteRequest := &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(metadata),
	}

	_, err = s.s3.DeleteObject(ctx, deleteRequest)
	if err != nil {
		return
	}

	key := fmt.Sprintf("%s/%s", token, filename)
	deleteRequest = &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}

	_, err = s.s3.DeleteObject(ctx, deleteRequest)

	return
}

// Put saves a file on storage
func (s *S3Storage) Put(ctx context.Context, token string, filename string, reader io.Reader, contentType string, _ uint64) (err error) {
	key := fmt.Sprintf("%s/%s", token, filename)

	s.logger.Printf("Uploading file %s to S3 Bucket", filename)

	var expire *time.Time
	if s.purgeDays.Hours() > 0 {
		expire = aws.Time(time.Now().Add(s.purgeDays))
	}

	_, err = s.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        reader,
		Expires:     expire,
		ContentType: aws.String(contentType),
	})

	return
}

// IsRangeSupported returns true because S3 supports HTTP Range requests.
func (s *S3Storage) IsRangeSupported() bool { return true }

func getAwsConfig(ctx context.Context, accessKey, secretKey string) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx,
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     accessKey,
				SecretAccessKey: secretKey,
				SessionToken:    "",
			},
		}),
	)
}
