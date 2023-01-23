package skeleton

import (
	"net/http"
	"time"

	"github.com/DRK-Blutspende-BaWueHe/skeleton/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type instrumentTO struct {
	ID                 uuid.UUID          `json:"id"`
	Name               string             `json:"name"`
	ProtocolID         uuid.UUID          `json:"protocolId"`
	ProtocolName       Protocol           `json:"type"`
	Enabled            bool               `json:"enabled"`
	ConnectionMode     ConnectionMode     `json:"connectionMode"`
	ResultMode         ResultMode         `json:"runningMode"`
	CaptureResults     bool               `json:"captureResults"`
	CaptureDiagnostics bool               `json:"captureDiagnostics"`
	ReplyToQuery       bool               `json:"replyToQuery"`
	Status             string             `json:"status"`
	FileEncoding       string             `json:"fileEncoding"`
	Timezone           string             `json:"timezone"`
	Hostname           string             `json:"hostname"`
	ClientPort         *int               `json:"clientPort"`
	AnalyteMappings    []analyteMappingTO `json:"analyteMappings"`
	RequestMappings    []requestMappingTO `json:"requestMappings"`
}

type listInstrumentTO struct {
	ID           uuid.UUID  `json:"id"`
	Name         string     `json:"name"`
	ProtocolName Protocol   `json:"type"`
	Status       string     `json:"status"`
	ResultMode   ResultMode `json:"runningMode"`
}

type analyteMappingTO struct {
	ID                uuid.UUID          `json:"id"`
	InstrumentAnalyte string             `json:"instrumentAnalyte"`
	AnalyteID         uuid.UUID          `json:"analyteId"`
	ChannelMappings   []channelMappingTO `json:"channelMappings"`
	ResultMappings    []resultMappingTO  `json:"resultMappings"`
	ResultType        ResultType         `json:"resultType"`
}

type requestMappingTO struct {
	ID         uuid.UUID   `json:"id"`
	Code       string      `json:"code"`
	AnalyteIDs []uuid.UUID `json:"requestMappingAnalyteIds"`
}

type channelMappingTO struct {
	ID                uuid.UUID `json:"id"`
	InstrumentChannel string    `json:"instrumentChannel"`
	ChannelID         uuid.UUID `json:"channelId"`
}

type resultMappingTO struct {
	ID    uuid.UUID `json:"id"`
	Key   string    `json:"key"`
	Value string    `json:"value"`
	Index int       `json:"index"`
}

type protocolAbilityTO struct {
	ConnectionMode          ConnectionMode `json:"connectionMode"`
	Abilities               []Ability      `json:"abilities"`
	RequestMappingAvailable bool           `json:"requestMappingAvailable"`
}

type supportedProtocolTO struct {
	ID                uuid.UUID           `json:"id"`
	Name              Protocol            `json:"name"`
	Description       *string             `json:"description"`
	ProtocolAbilities []protocolAbilityTO `json:"protocolAbilities"`
}

type supportedManufacturerTestTO struct {
	TestName          string   `json:"testName"`
	Channels          []string `json:"channels"`
	ValidResultValues []string `json:"validResultValues"`
}

type analysisRequestInfoTO struct {
	RequestID uuid.UUID `json:"requestId"`
	//ResultID          *uuid.UUID `json:"-"`
	SampleCode string    `json:"sampleCode"`
	AnalyteID  uuid.UUID `json:"analyteId"`
	//AnalyteMappingsID *uuid.UUID `json:"-"`
	WorkItemID       uuid.UUID  `json:"workitemId"` // Todo
	RequestCreatedAt time.Time  `json:"createdAt"`
	TestName         *string    `json:"testName"`
	TestResult       *string    `json:"testResult"`
	BatchCreatedAt   *time.Time `json:"transmissionDate"`
	Status           string     `json:"status"`
	//SentToCerberusAt  *time.Time `json:"-"`
	SourceIP string `json:"sourceIP"` // Todo
	//InstrumentID      *uuid.UUID `json:"-"`
	MappingError bool `json:"mappingError"`
}

func (api *api) GetInstruments(c *gin.Context) {
	instruments, err := api.instrumentService.GetInstruments(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, "GetInstruments Error")
		return
	}

	instrumentTOs := make([]listInstrumentTO, len(instruments))

	for i := range instruments {
		instrumentTOs[i] = convertInstrumentToListInstrumentTO(instruments[i])
	}

	c.JSON(http.StatusOK, instrumentTOs)
}

func (api *api) GetInstrumentByID(c *gin.Context) {
	id, err := uuid.Parse(c.Param("instrumentId"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, "GetInstrumentByID Error")
		return
	}

	instrument, err := api.instrumentService.GetInstrumentByID(c, id)
	if err != nil {
		if err == ErrInstrumentNotFound {
			c.AbortWithStatus(http.StatusNotFound)
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, "GetInstrumentByID Error")
		return
	}

	c.JSON(http.StatusOK, convertInstrumentToInstrumentTO(instrument))
}

func (api *api) CreateInstrument(c *gin.Context) {
	instrumentTO := instrumentTO{}
	err := c.ShouldBindJSON(&instrumentTO)
	if err != nil {
		log.Error().Err(err).Msg("Create instrument failed! Can't parse request body!")
		c.AbortWithStatusJSON(http.StatusBadRequest, "CreateInstrument Error")
		return
	}

	instrument := convertInstrumentTOToInstrument(instrumentTO)

	if !isRequestMappingValid(instrument) {
		log.Error().Msg("RequestMapping is not Valid")
		c.AbortWithStatusJSON(http.StatusBadRequest, "CreateInstrument Error")
		return
	}

	savedInstrumentID, err := api.instrumentService.CreateInstrument(c, instrument)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, "CreateInstrument Error")
		return
	}

	c.JSON(http.StatusOK, savedInstrumentID)
}

func (api *api) UpdateInstrument(c *gin.Context) {
	instrumentTO := instrumentTO{}

	err := c.ShouldBindJSON(&instrumentTO)
	if err != nil {
		log.Error().Err(err).Msg("Update instrument failed! Can't bind request body!")
		c.AbortWithStatusJSON(http.StatusBadRequest, "api_errors.InvalidRequestBody")
		return
	}

	instrument := convertInstrumentTOToInstrument(instrumentTO)

	err = api.instrumentService.UpdateInstrument(c, instrument)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, "api_errors.InternalServerError")
		return
	}

	c.Status(http.StatusNoContent)
}

func (api *api) DeleteInstrument(c *gin.Context) {
	id, err := uuid.Parse(c.Param("instrumentId"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, "DeleteInstrument Error")
		return
	}

	err = api.instrumentService.DeleteInstrument(c, id)
	if err != nil {
		if err == ErrInstrumentNotFound {
			c.AbortWithStatus(http.StatusNotFound)
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, "Error")
		return
	}

	c.Status(http.StatusNoContent)
}

func (api *api) GetSupportedProtocols(c *gin.Context) {
	supportedInstruments, err := api.instrumentService.GetSupportedProtocols(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, "GetSupportedProtocols Error")
		return
	}

	c.JSON(http.StatusOK, convertSupportedProtocolsToSupportedProtocolTOs(supportedInstruments))
}

func (api *api) GetProtocolAbilities(c *gin.Context) {
	protocolID, err := uuid.Parse(c.Param("protocolVersionId"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, "GetProtocolAbilities Error")
		return
	}

	protocolAbilities, err := api.instrumentService.GetProtocolAbilities(c, protocolID)
	if err != nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	c.JSON(http.StatusOK, convertProtocolAbilitiesToProtocolAbilitiesTOs(protocolAbilities))
}

func (api *api) GetManufacturerTests(c *gin.Context) {
	protocolID, err := uuid.Parse(c.Param("protocolVersionId"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, "GetProtocolAbilities Error")
		return
	}

	instrumentID := uuid.Nil
	instrumentIDString, ok := c.GetQuery("instrumentId")
	if ok {
		instrumentID, err = uuid.Parse(instrumentIDString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, "malformed instrument ID")
			return
		}
	}

	tests, err := api.instrumentService.GetManufacturerTests(c, instrumentID, protocolID)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	c.JSON(http.StatusOK, convertSupportedManufacturerTestsToSupportedManufacturerTestTOs(tests))
}

func (api *api) GetAnalysisRequestsInfo(c *gin.Context) {
	instrumentID, err := uuid.Parse(c.Param("instrumentId"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
		return
	}

	var pageable Pageable
	err = c.ShouldBindQuery(&pageable)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, "malformed pageable data")
		return
	}

	analysisRequestInfoList, totalCount, err := api.analysisService.GetAnalysisRequestsInfo(c, instrumentID, pageable)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, NewPage(pageable, totalCount, convertAnalysisRequestInfoListToAnalysisRequestInfoTOList(analysisRequestInfoList)))
}

//// AddRequestToTransferQueue
//// @Summary Add Request to Transfer Queue
//// @Description Add a Request to the transfer queue to retransmit again
//// @Tags AnalysisRequest
//// @Produce json
//// @Param requestID path string true "ID of the Request"
//// @Success 200 "OK"
//// @Failure 400 "Bad Request"
//// @Failure 500 {object} model.HTTPError "Internal Server Error"
//// @Router /v1/instruments/request/{requestID}/add-to-queue [GET]
//func (api *api) AddRequestToTransferQueue(c *gin.Context) {
//	requestID, err := uuid.Parse(c.Param("requestID"))
//	if err != nil {
//		log.Error().Err(err).Msg("AddRequestToTransferQueue: invalid requestID parameter")
//		c.JSON(http.StatusBadRequest, api_errors.ErrInvalidIDParameter)
//		return
//	}
//
//	request, err := h.analysisRequestService.GetRequestByID(requestID)
//	if err != nil {
//		if err == sql.ErrNoRows {
//			c.Status(http.StatusOK)
//			return
//		}
//
//		log.Error().Err(err).Msg("Can not fetch requestID")
//		c.JSON(http.StatusInternalServerError, api_errors.InternalServerError)
//		return
//	}
//
//	skeletonRequest := mapAnalysisRequestToSkeletonAnalysisRequest(request)
//	h.analysisRequestService.RetriggerTransferOfRequest(skeletonRequest)
//
//	c.Status(http.StatusOK)
//}
//
//// GetChannelResultsForRequest
//// @Summary Get Channel Results for requestID
//// @Description Get Channel Results for requestID
//// @Tags AnalysisRequest
//// @Produce json
//// @Param requestID path string true "ID of the Request"
//// @Success 200 {object} []model.ChannelResultDetailTO "OK"
//// @Failure 400 "Bad Request"
//// @Failure 500 string string "Internal Server Error"
//// @Router /v1/instruments/channel-results/{requestID} [GET]
//func (api *api) GetChannelResultsForRequest(c *gin.Context) {
//	requestID, err := uuid.Parse(c.Param("requestID"))
//	if err != nil {
//		log.Error().Err(err).Msg("GetCIAHTTPRequestHistory: invalid requestID parameter")
//		c.Status(http.StatusBadRequest)
//		return
//	}
//
//	_, err = h.analysisRequestService.GetRequestByID(requestID)
//	if err != nil {
//		if err == sql.ErrNoRows {
//			c.Status(http.StatusNotFound)
//			return
//		}
//		log.Error().Err(err).Msg("Can not get request by given ID")
//		c.JSON(http.StatusBadRequest, "Can not get request by ID")
//		return
//	}
//
//	c.JSON(http.StatusOK, []model.ChannelResultDetailTO{})
//}
//
//func (api *api) AddTransmissionsBatchToTransferQueue(c *gin.Context) {
//	var transmissionBatchData apiModel.TransmissionBatch
//
//	err := c.ShouldBindJSON(&transmissionBatchData)
//	if err != nil {
//		c.AbortWithStatusJSON(http.StatusBadRequest, api_errors.InvalidRequestBody)
//		return
//	}
//
//	sampleCodes, err := h.analysisResultService.GetSampleCodesByBatchIDs(transmissionBatchData.TransmissionIDs)
//	if err != nil {
//		c.AbortWithStatusJSON(http.StatusBadRequest, api_errors.InternalServerError)
//		return
//	}
//
//	if len(sampleCodes) > 0 {
//		err = h.analysisRequestService.RetriggerResultTransferBySampleCodes(sampleCodes)
//		if err != nil {
//			log.Error().Err(err).Msg("Can not retrigger Transfer for sampleCodes")
//			c.AbortWithStatusJSON(http.StatusBadRequest, api_errors.InternalServerError)
//			return
//		}
//	}
//
//	c.Status(http.StatusOK)
//}

func convertInstrumentToListInstrumentTO(instrument Instrument) listInstrumentTO {
	return listInstrumentTO{
		ID:           instrument.ID,
		Name:         instrument.Name,
		ProtocolName: instrument.ProtocolName,
		Status:       instrument.Status,
		ResultMode:   instrument.ResultMode,
	}
}

func convertInstrumentTOToInstrument(instrumentTO instrumentTO) Instrument {
	model := Instrument{
		ID:                 instrumentTO.ID,
		Name:               instrumentTO.Name,
		ProtocolID:         instrumentTO.ProtocolID,
		ProtocolName:       instrumentTO.ProtocolName,
		Enabled:            instrumentTO.Enabled,
		ConnectionMode:     instrumentTO.ConnectionMode,
		ResultMode:         instrumentTO.ResultMode,
		CaptureResults:     instrumentTO.CaptureResults,
		CaptureDiagnostics: instrumentTO.CaptureDiagnostics,
		ReplyToQuery:       instrumentTO.ReplyToQuery,
		FileEncoding:       instrumentTO.FileEncoding,
		Timezone:           instrumentTO.Timezone,
		Hostname:           instrumentTO.Hostname,
		ClientPort:         instrumentTO.ClientPort,
		AnalyteMappings:    make([]AnalyteMapping, len(instrumentTO.AnalyteMappings)),
		RequestMappings:    make([]RequestMapping, len(instrumentTO.RequestMappings)),
	}

	if instrumentTO.Status == "" {
		model.Status = string(InstrumentOffline)
	}

	for i, analyteMapping := range instrumentTO.AnalyteMappings {
		model.AnalyteMappings[i] = convertAnalyteMappingTOToAnalyteMapping(analyteMapping)
	}

	for i, requestMapping := range instrumentTO.RequestMappings {
		model.RequestMappings[i] = convertRequestMappingTOToRequestMapping(requestMapping)
	}

	return model
}

func convertInstrumentToInstrumentTO(instrument Instrument) instrumentTO {
	model := instrumentTO{
		ID:                 instrument.ID,
		Name:               instrument.Name,
		ProtocolID:         instrument.ProtocolID,
		ProtocolName:       instrument.ProtocolName,
		Enabled:            instrument.Enabled,
		ConnectionMode:     instrument.ConnectionMode,
		ResultMode:         instrument.ResultMode,
		CaptureResults:     instrument.CaptureResults,
		CaptureDiagnostics: instrument.CaptureDiagnostics,
		ReplyToQuery:       instrument.ReplyToQuery,
		Status:             instrument.Status,
		FileEncoding:       instrument.FileEncoding,
		Timezone:           instrument.Timezone,
		Hostname:           instrument.Hostname,
		ClientPort:         instrument.ClientPort,
		AnalyteMappings:    make([]analyteMappingTO, len(instrument.AnalyteMappings)),
		RequestMappings:    make([]requestMappingTO, len(instrument.RequestMappings)),
	}

	for i, analyteMapping := range instrument.AnalyteMappings {
		model.AnalyteMappings[i] = convertAnalyteMappingToAnalyteMappingTO(analyteMapping)
	}

	for i, requestMapping := range instrument.RequestMappings {
		model.RequestMappings[i] = convertRequestMappingToRequestMappingTO(requestMapping)
	}

	return model
}

func convertAnalyteMappingTOToAnalyteMapping(analyteMappingTO analyteMappingTO) AnalyteMapping {
	model := AnalyteMapping{
		ID:                analyteMappingTO.ID,
		InstrumentAnalyte: analyteMappingTO.InstrumentAnalyte,
		AnalyteID:         analyteMappingTO.AnalyteID,
		ChannelMappings:   make([]ChannelMapping, len(analyteMappingTO.ChannelMappings)),
		ResultMappings:    make([]ResultMapping, len(analyteMappingTO.ResultMappings)),
		ResultType:        analyteMappingTO.ResultType,
	}

	for i, channelMapping := range analyteMappingTO.ChannelMappings {
		model.ChannelMappings[i] = convertChannelMappingTOToChannelMapping(channelMapping)
	}

	for i, resultMapping := range analyteMappingTO.ResultMappings {
		model.ResultMappings[i] = convertResultMappingTOToResultMapping(resultMapping)
	}

	return model
}

func convertAnalyteMappingToAnalyteMappingTO(analyteMapping AnalyteMapping) analyteMappingTO {
	model := analyteMappingTO{
		ID:                analyteMapping.ID,
		InstrumentAnalyte: analyteMapping.InstrumentAnalyte,
		AnalyteID:         analyteMapping.AnalyteID,
		ChannelMappings:   make([]channelMappingTO, len(analyteMapping.ChannelMappings)),
		ResultMappings:    make([]resultMappingTO, len(analyteMapping.ResultMappings)),
		ResultType:        analyteMapping.ResultType,
	}

	for i, channelMapping := range analyteMapping.ChannelMappings {
		model.ChannelMappings[i] = convertChannelMappingToChannelMappingTO(channelMapping)
	}

	for i, resultMapping := range analyteMapping.ResultMappings {
		model.ResultMappings[i] = convertResultMappingToResultMappingTO(resultMapping)
	}

	return model
}

func convertRequestMappingTOToRequestMapping(requestMappingTO requestMappingTO) RequestMapping {
	return RequestMapping{
		ID:         requestMappingTO.ID,
		Code:       requestMappingTO.Code,
		AnalyteIDs: requestMappingTO.AnalyteIDs,
	}
}

func convertRequestMappingToRequestMappingTO(requestMapping RequestMapping) requestMappingTO {
	return requestMappingTO{
		ID:         requestMapping.ID,
		Code:       requestMapping.Code,
		AnalyteIDs: requestMapping.AnalyteIDs,
	}
}

func convertChannelMappingTOToChannelMapping(channelMappingTO channelMappingTO) ChannelMapping {
	return ChannelMapping{
		ID:                channelMappingTO.ID,
		InstrumentChannel: channelMappingTO.InstrumentChannel,
		ChannelID:         channelMappingTO.ChannelID,
	}
}

func convertChannelMappingToChannelMappingTO(channelMapping ChannelMapping) channelMappingTO {
	return channelMappingTO{
		ID:                channelMapping.ID,
		InstrumentChannel: channelMapping.InstrumentChannel,
		ChannelID:         channelMapping.ChannelID,
	}
}

func convertResultMappingTOToResultMapping(resultMappingTO resultMappingTO) ResultMapping {
	return ResultMapping{
		ID:    resultMappingTO.ID,
		Key:   resultMappingTO.Key,
		Value: resultMappingTO.Value,
		Index: resultMappingTO.Index,
	}
}

func convertResultMappingToResultMappingTO(resultMapping ResultMapping) resultMappingTO {
	return resultMappingTO{
		ID:    resultMapping.ID,
		Key:   resultMapping.Key,
		Value: resultMapping.Value,
		Index: resultMapping.Index,
	}
}

func convertSupportedProtocolToSupportedProtocolTO(supportedProtocol SupportedProtocol) supportedProtocolTO {
	to := supportedProtocolTO{
		ID:                supportedProtocol.ID,
		Name:              supportedProtocol.Name,
		Description:       supportedProtocol.Description,
		ProtocolAbilities: make([]protocolAbilityTO, len(supportedProtocol.ProtocolAbilities)),
	}
	for i := range supportedProtocol.ProtocolAbilities {
		to.ProtocolAbilities[i] = convertProtocolAbilityToProtocolAbilityTO(supportedProtocol.ProtocolAbilities[i])
	}
	return to
}

func convertSupportedProtocolsToSupportedProtocolTOs(supportedProtocols []SupportedProtocol) []supportedProtocolTO {
	tos := make([]supportedProtocolTO, len(supportedProtocols))
	for i := range supportedProtocols {
		tos[i] = convertSupportedProtocolToSupportedProtocolTO(supportedProtocols[i])
	}
	return tos
}

func convertProtocolAbilityToProtocolAbilitiesTO(protocolAbility ProtocolAbility) protocolAbilityTO {
	to := protocolAbilityTO{
		ConnectionMode:          protocolAbility.ConnectionMode,
		Abilities:               protocolAbility.Abilities,
		RequestMappingAvailable: protocolAbility.RequestMappingAvailable,
	}
	return to
}

func convertProtocolAbilitiesToProtocolAbilitiesTOs(protocolAbilities []ProtocolAbility) []protocolAbilityTO {
	tos := make([]protocolAbilityTO, len(protocolAbilities))
	for i := range protocolAbilities {
		tos[i] = convertProtocolAbilityToProtocolAbilitiesTO(protocolAbilities[i])
	}
	return tos
}

func convertProtocolAbilityToProtocolAbilityTO(protocolAbility ProtocolAbility) protocolAbilityTO {
	return protocolAbilityTO{
		ConnectionMode:          protocolAbility.ConnectionMode,
		Abilities:               protocolAbility.Abilities,
		RequestMappingAvailable: protocolAbility.RequestMappingAvailable,
	}
}

func convertSupportedManufacturerTestToSupportedManufacturerTestTO(supportedManufacturerTest SupportedManufacturerTests) supportedManufacturerTestTO {
	return supportedManufacturerTestTO{
		TestName:          supportedManufacturerTest.TestName,
		Channels:          supportedManufacturerTest.Channels,
		ValidResultValues: supportedManufacturerTest.ValidResultValues,
	}
}

func convertSupportedManufacturerTestsToSupportedManufacturerTestTOs(supportedManufacturerTests []SupportedManufacturerTests) []supportedManufacturerTestTO {
	tos := make([]supportedManufacturerTestTO, len(supportedManufacturerTests))
	for i := range supportedManufacturerTests {
		tos[i] = convertSupportedManufacturerTestToSupportedManufacturerTestTO(supportedManufacturerTests[i])
	}
	return tos
}

func convertAnalysisRequestInfoToAnalysisRequestInfoTO(analysisRequestInfo AnalysisRequestInfo) analysisRequestInfoTO {
	return analysisRequestInfoTO{
		RequestID:        analysisRequestInfo.ID,
		SampleCode:       analysisRequestInfo.SampleCode,
		AnalyteID:        analysisRequestInfo.AnalyteID,
		WorkItemID:       analysisRequestInfo.WorkItemID,
		TestName:         analysisRequestInfo.TestName,
		TestResult:       analysisRequestInfo.TestResult,
		RequestCreatedAt: analysisRequestInfo.RequestCreatedAt,
		BatchCreatedAt:   analysisRequestInfo.BatchCreatedAt,
		Status:           analysisRequestInfo.Status,
		SourceIP:         analysisRequestInfo.SourceIP,
		MappingError:     analysisRequestInfo.MappingError,
	}
}

func convertAnalysisRequestInfoListToAnalysisRequestInfoTOList(analysisRequestInfoList []AnalysisRequestInfo) []analysisRequestInfoTO {
	tos := make([]analysisRequestInfoTO, len(analysisRequestInfoList))
	for i := range analysisRequestInfoList {
		tos[i] = convertAnalysisRequestInfoToAnalysisRequestInfoTO(analysisRequestInfoList[i])
	}
	return tos
}

// Todo ZsN - Improve this
func isRequestMappingValid(instrument Instrument) bool {
	requestMappings := instrument.RequestMappings
	codes := make([]string, 0)
	for _, requestMapping := range requestMappings {
		if len(requestMapping.AnalyteIDs) < 1 {
			return false
		}

		// Check if only each code is once created
		if utils.SliceContains(requestMapping.Code, codes) {
			return false
		}
		codes = append(codes, requestMapping.Code)
	}
	return true
}
