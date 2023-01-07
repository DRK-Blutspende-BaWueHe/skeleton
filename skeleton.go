package skeleton

import (
	"context"
	"github.com/DRK-Blutspende-BaWueHe/skeleton/migrator"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type skeleton struct {
	sqlConn *sqlx.DB
	dbSchema        string
	callBackHandler SkeletonCallbackHandlerV1
	migrator           migrator.SkeletonMigrator
	analysisService    AnalysisService
	analysisRepository AnalysisRepository
	resultsBuffer      []AnalysisResultV1
	resultsChan        chan AnalysisResultV1
	resultBatchesChan chan []AnalysisResultV1
	cerberusClient    CerberusV1
}

func (s *skeleton) SetCallbackHandler(eventHandler SkeletonCallbackHandlerV1) {
	s.callBackHandler = eventHandler
}
func (s *skeleton) GetCallbackHandler() SkeletonCallbackHandlerV1 {
	return s.callBackHandler
}

func (s *skeleton) Log(instrumentID uuid.UUID, msg string) {
	log.Info().Interface("instrumentId", instrumentID).Msg(msg)
}

func (s *skeleton) LogError(instrumentID uuid.UUID, err error) {
	log.Error().Interface("instrumentId", instrumentID).Err(err).Msg("")
}

func (s *skeleton) LogDebug(instrumentID uuid.UUID, msg string) {
	log.Debug().Interface("instrumentId", instrumentID).Msg(msg)
}

func (s *skeleton) GetAnalysisRequestWithNoResults(currentPage, itemsPerPage int) (requests []AnalysisRequestV1, maxPages int, err error) {

	return []AnalysisRequestV1{}, 0, nil
}

func (s *skeleton) GetAnalysisRequestsBySampleCode(sampleCode string) ([]AnalysisRequestV1, error) {
	return []AnalysisRequestV1{}, nil
}

func (s *skeleton) GetAnalysisRequestsBySampleCodes(sampleCodes []string) ([]AnalysisRequestV1, error) {
	return []AnalysisRequestV1{}, nil
}

func (s *skeleton) GetRequestMappingsByInstrumentID(instrumentID uuid.UUID) ([]RequestMappingV1, error) {
	return []RequestMappingV1{}, nil
}

func (s *skeleton) SubmitAnalysisResult(ctx context.Context, resultData AnalysisResultV1, submitTypes ...SubmitType) error {
	tx, err := s.analysisRepository.CreateTransaction()
	if err != nil {
		return err
	}
	_, err = s.analysisRepository.WithTransaction(tx).CreateAnalysisResultsBatch(ctx, []AnalysisResultV1{resultData})
	if err != nil {
		return err
	}

	s.resultsChan <- resultData
	return nil
}

func (s *skeleton) GetInstrument(instrumentID uuid.UUID) (InstrumentV1, error) {
	return InstrumentV1{}, nil
}

func (s *skeleton) GetInstruments() ([]InstrumentV1, error) {
	return []InstrumentV1{}, nil
}

func (s *skeleton) FindAnalyteByManufacturerTestCode(instrument InstrumentV1, testCode string) AnalyteMappingV1 {
	return AnalyteMappingV1{}
}

func (s *skeleton) FindResultMapping(searchvalue string, mapping []ResultMappingV1) (string, error) {
	return "", nil
}

func (s *skeleton) migrateUp(ctx context.Context, db *sqlx.DB, schemaName string) error {
	return s.migrator.Run(ctx, db, schemaName)
}

func (s *skeleton) Start() error {
	err := s.migrateUp(context.Background(), s.sqlConn, s.dbSchema)
	if err != nil {
		return err
	}

	go s.processAnalysisResults(context.Background())
	go s.processAnalysisResultBatches(context.Background())
	return nil
}

func (s *skeleton) processAnalysisResults(ctx context.Context) {
	for {
		select {
		case result, ok := <-s.resultsChan:
			if !ok {
				log.Fatal().Msg("processing analysis results stopped: results channel closed")
			}
			s.resultsBuffer = append(s.resultsBuffer, result)
			if len(s.resultsBuffer) >= 500 {
				s.resultBatchesChan <- s.resultsBuffer
				s.resultsBuffer = make([]AnalysisResultV1, 0, 500)
			}
		case <-time.After(3 * time.Second):
			s.resultBatchesChan <- s.resultsBuffer
			s.resultsBuffer = make([]AnalysisResultV1, 0, 500)
		}
	}
}

const maxRetryCount = 30

func (s *skeleton) processAnalysisResultBatches(ctx context.Context) {
	for {
		resultsBatch, ok := <-s.resultBatchesChan
		if !ok {
			log.Fatal().Msg("processing analysis result batches stopped: resultBatches channel closed")
		}
		creationStatuses, err := s.cerberusClient.PostAnalysisResultBatch(resultsBatch)
		if err != nil {
			time.AfterFunc(30*time.Second, func() {
				s.resultBatchesChan <- resultsBatch
			})
			continue
		}
		for i, status := range creationStatuses {
			err = s.analysisRepository.UpdateResultTransmissionData(ctx, resultsBatch[i].ID, status.Success, status.ErrorMessage)
			if !status.Success && resultsBatch[i].RetryCount < maxRetryCount {
				time.AfterFunc(30*time.Second, func() {
					s.resultsChan <- resultsBatch[i]
				})
			}
		}
	}
}

func NewSkeleton(sqlConn *sqlx.DB, dbSchema string, migrator migrator.SkeletonMigrator, analysisService AnalysisService, analysisRepository AnalysisRepository, cerberusClient CerberusV1) SkeletonAPI {
	return &skeleton{
		sqlConn:sqlConn,
		dbSchema: dbSchema,
		migrator:           migrator,
		analysisService:    analysisService,
		analysisRepository: analysisRepository,
		cerberusClient:     cerberusClient,
		resultsBuffer:      make([]AnalysisResultV1, 0, 500),
		resultsChan:        make(chan AnalysisResultV1, 500),
		resultBatchesChan:  make(chan []AnalysisResultV1, 10),
	}
}