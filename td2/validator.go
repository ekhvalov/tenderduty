package tenderduty

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blockpane/tenderduty/v2/pkg/namada"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	slashing "github.com/cosmos/cosmos-sdk/x/slashing/types"
	staking "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/near/borsh-go"
	rpchttp "github.com/tendermint/tendermint/rpc/client/http"
)

// ValInfo holds most of the stats/info used for secondary alarms. It is refreshed roughly every minute.
type ValInfo struct {
	Moniker    string `json:"moniker"`
	Bonded     bool   `json:"bonded"`
	Jailed     bool   `json:"jailed"`
	Tombstoned bool   `json:"tombstoned"`
	Missed     int64  `json:"missed"`
	Window     int64  `json:"window"`
	Conspub    []byte `json:"conspub"`
	Valcons    string `json:"valcons"`
}

// GetValInfo the first bool is used to determine if extra information about the validator should be printed.
func (cc *ChainConfig) GetValInfo(first bool) (err error) {
	if cc.client == nil {
		return errors.New("nil rpc client")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if cc.valInfo == nil {
		cc.valInfo = &ValInfo{}
	}

	res, err := cc.client.ABCIQuery(ctx, fmt.Sprintf("/vp/pos/validator/state/%s", cc.NamadaEstablishedAddress), nil)
	if err != nil {
		return err
	}

	validatorState := namada.ValidatorStateInfo{}
	err = borsh.Deserialize(&validatorState, res.Response.Value)
	if err != nil {
		return err
	}

	// Fetch info from /cosmos.staking.v1beta1.Query/Validator
	// it's easier to ask people to provide valoper since it's readily available on
	// explorers, so make it easy and lookup the consensus key for them.
	cc.valInfo.Conspub, cc.valInfo.Moniker, cc.valInfo.Jailed, cc.valInfo.Bonded, err = getVal(ctx, cc.client, cc.ValAddress)

	if cc.NamadaEstablishedAddress != "" {
		var info *ValInfo
		info, err = getNamadaValidatorInfo(ctx, cc.client, cc.NamadaEstablishedAddress)
		if err != nil {
			return err
		}
		if info.Moniker != "" {
			cc.valInfo.Moniker = info.Moniker
		}
		cc.valInfo.Jailed = info.Jailed
		cc.valInfo.Bonded = info.Bonded
	}

	if err != nil {
		return
	}
	if first && cc.valInfo.Bonded {
		l(fmt.Sprintf("⚙️ found %s (%s) in validator set", cc.ValAddress, cc.valInfo.Moniker))
	} else if first && !cc.valInfo.Bonded {
		l(fmt.Sprintf("❌ %s (%s) is INACTIVE", cc.ValAddress, cc.valInfo.Moniker))
	}

	if strings.Contains(cc.ValAddress, "valcons") {
		// no need to change prefix for signing info query
		cc.valInfo.Valcons = cc.ValAddress
	} else {
		// need to know the prefix for when we serialize the slashing info query, this is too fragile.
		// for now, we perform specific chain overrides based on known values because the valoper is used
		// in so many places.
		var prefix string
		split := strings.Split(cc.ValAddress, "valoper")
		if len(split) != 2 {
			if pre, ok := altValopers.getAltPrefix(cc.ValAddress); ok {
				cc.valInfo.Valcons, err = bech32.ConvertAndEncode(pre, cc.valInfo.Conspub[:20])
				if err != nil {
					return
				}
			} else {
				err = errors.New("❓ could not determine bech32 prefix from valoper address: " + cc.ValAddress)
				return
			}
		} else {
			prefix = split[0] + "valcons"
			cc.valInfo.Valcons, err = bech32.ConvertAndEncode(prefix, cc.valInfo.Conspub[:20])
			if err != nil {
				return
			}
		}
		if first {
			l("⚙️", cc.ValAddress[:20], "... is using consensus key:", cc.valInfo.Valcons)
		}

	}

	var signingInfo *slashing.ValidatorSigningInfo
	if cc.NamadaEstablishedAddress != "" {
		signingInfo, err = getNamadaSigningInfo(ctx, cc.client, cc.valInfo.Valcons)
	} else {
		signingInfo, err = getTendermintSigningInfo(ctx, cc.client, cc.valInfo.Valcons)
	}
	if err != nil {
		return
	}
	cc.valInfo.Tombstoned = signingInfo.Tombstoned
	if cc.valInfo.Tombstoned {
		l(fmt.Sprintf("❗️☠️ %s (%s) is tombstoned 🪦❗️", cc.ValAddress, cc.valInfo.Moniker))
	}
	cc.valInfo.Missed = signingInfo.MissedBlocksCounter
	if td.Prom {
		td.statsChan <- cc.mkUpdate(metricWindowMissed, float64(cc.valInfo.Missed), "")
	}

	// finally get the signed blocks window
	if cc.valInfo.Window == 0 {
		var params *slashing.Params
		if cc.NamadaEstablishedAddress != "" {
			params, err = getNamadaSlashingParams(ctx, cc.client)
		} else {
			params, err = getTendermintSlashingParams(ctx, cc.client)
		}
		if err != nil {
			return
		}

		if first && td.Prom {
			td.statsChan <- cc.mkUpdate(metricWindowSize, float64(params.SignedBlocksWindow), "")
			td.statsChan <- cc.mkUpdate(metricTotalNodes, float64(len(cc.Nodes)), "")
		}
		cc.valInfo.Window = params.SignedBlocksWindow
	}
	return
}

// getVal returns the public key, moniker, and if the validator is jailed.
func getVal(ctx context.Context, client *rpchttp.HTTP, valoper string) (pub []byte, moniker string, jailed, bonded bool, err error) {
	if strings.Contains(valoper, "valcons") {
		_, bz, err := bech32.DecodeAndConvert(valoper)
		if err != nil {
			return nil, "", false, false, errors.New("could not decode and convert your address" + valoper)
		}

		hexAddress := fmt.Sprintf("%X", bz)
		return ToBytes(hexAddress), valoper, false, true, nil
	}

	q := staking.QueryValidatorRequest{
		ValidatorAddr: valoper,
	}
	b, err := q.Marshal()
	if err != nil {
		return
	}
	resp, err := client.ABCIQuery(ctx, "/cosmos.staking.v1beta1.Query/Validator", b)
	if err != nil {
		return
	}
	if resp.Response.Value == nil {
		return nil, "", false, false, errors.New("could not find validator " + valoper)
	}
	val := &staking.QueryValidatorResponse{}
	err = val.Unmarshal(resp.Response.Value)
	if err != nil {
		return
	}
	if val.Validator.ConsensusPubkey == nil {
		return nil, "", false, false, errors.New("got invalid consensus pubkey for " + valoper)
	}

	pubBytes := make([]byte, 0)
	switch val.Validator.ConsensusPubkey.TypeUrl {
	case "/cosmos.crypto.ed25519.PubKey":
		pk := ed25519.PubKey{}
		err = pk.Unmarshal(val.Validator.ConsensusPubkey.Value)
		if err != nil {
			return
		}
		pubBytes = pk.Address().Bytes()
	case "/cosmos.crypto.secp256k1.PubKey":
		pk := secp256k1.PubKey{}
		err = pk.Unmarshal(val.Validator.ConsensusPubkey.Value)
		if err != nil {
			return
		}
		pubBytes = pk.Address().Bytes()
	}
	if len(pubBytes) == 0 {
		return nil, "", false, false, errors.New("could not get pubkey for" + valoper)
	}

	return pubBytes, val.Validator.GetMoniker(), val.Validator.Jailed, val.Validator.Status == 3, nil
}

func ToBytes(address string) []byte {
	bz, _ := hex.DecodeString(strings.ToLower(address))
	return bz
}

func getTendermintSigningInfo(ctx context.Context, client *rpchttp.HTTP, valconsAddress string) (*slashing.ValidatorSigningInfo, error) {
	// get current signing information (tombstoned, missed block count)
	request := slashing.QuerySigningInfoRequest{ConsAddress: valconsAddress}
	requestData, err := request.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal signing info request: %w", err)
	}

	response, err := client.ABCIQuery(ctx, "/cosmos.slashing.v1beta1.Query/SigningInfo", requestData)
	if err != nil {
		return nil, fmt.Errorf("query signing info: %w", err)
	}

	info := &slashing.QuerySigningInfoResponse{}
	err = info.Unmarshal(response.Response.Value)
	if err != nil {
		return nil, fmt.Errorf("unmarshal signing info response: %w", err)
	}

	return &info.ValSigningInfo, nil
}

func getNamadaSigningInfo(ctx context.Context, client *rpchttp.HTTP, valconsAddress string) (*slashing.ValidatorSigningInfo, error) {
	livenessInfo, err := getLivenessInfo(ctx, client)
	if err != nil {
		return nil, err
	}

	signingInfo := slashing.ValidatorSigningInfo{}

	_, hexAddressBytes, err := bech32.DecodeAndConvert(valconsAddress)
	hexAddress := strings.ToUpper(hex.EncodeToString(hexAddressBytes))
	if err != nil {
		return nil, fmt.Errorf("decode validator address: %w", err)
	}
	for _, v := range livenessInfo.Validators {
		if v.CometAddress == hexAddress {
			signingInfo.MissedBlocksCounter = int64(v.MissedVotes)
		}
	}

	return &signingInfo, nil
}

func getLivenessInfo(ctx context.Context, client *rpchttp.HTTP) (*namada.LivenessInfo, error) {
	resp, err := client.ABCIQuery(ctx, "/vp/pos/validator/liveness_info", nil)
	if err != nil {
		return nil, fmt.Errorf("query validator liveness_info: %w", err)
	}

	livenessInfo := namada.LivenessInfo{}
	err = borsh.Deserialize(&livenessInfo, resp.Response.Value)
	if err != nil {
		return nil, fmt.Errorf("unmarshal liveness info: %w", err)
	}

	return &livenessInfo, nil
}

func getTendermintSlashingParams(ctx context.Context, client *rpchttp.HTTP) (*slashing.Params, error) {
	qParams := &slashing.QueryParamsRequest{}
	var b []byte
	b, err := qParams.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal slashing params: %w", err)
	}

	resp, err := client.ABCIQuery(ctx, "/cosmos.slashing.v1beta1.Query/Params", b)
	if err != nil {
		return nil, fmt.Errorf("query slashing params: %w", err)
	}
	if resp.Response.Value == nil {
		return nil, errors.New("🛑 could not query slashing params, got empty response")
	}

	params := &slashing.QueryParamsResponse{}
	err = params.Unmarshal(resp.Response.Value)
	if err != nil {
		return nil, fmt.Errorf("unmarshal slashing params: %w", err)
	}

	return &params.Params, nil
}

func getNamadaSlashingParams(ctx context.Context, client *rpchttp.HTTP) (*slashing.Params, error) {
	livenessInfo, err := getLivenessInfo(ctx, client)
	if err != nil {
		return nil, err
	}

	return &slashing.Params{SignedBlocksWindow: int64(livenessInfo.LivenessWindowLen)}, nil
}

func getNamadaValidatorInfo(ctx context.Context, client *rpchttp.HTTP, establishedAddress string) (*ValInfo, error) {
	response, err := client.ABCIQuery(ctx, fmt.Sprintf("/vp/pos/validator/state/%s", establishedAddress), nil)
	if err != nil {
		return nil, fmt.Errorf("query validator state: %w", err)
	}

	state := namada.ValidatorStateInfo{}
	err = borsh.Deserialize(&state, response.Response.Value)
	if err != nil {
		return nil, fmt.Errorf("unmarshal validator state: %w", err)
	}
	info := ValInfo{}
	info.Bonded = state.State != nil && *state.State == namada.ValidatorStateConsensus
	info.Jailed = state.State != nil && *state.State == namada.ValidatorStateJailed

	response, err = client.ABCIQuery(ctx, fmt.Sprintf("/vp/pos/validator/metadata/%s", establishedAddress), nil)
	if err != nil {
		return nil, fmt.Errorf("query validator metadata: %w", err)
	}
	metadata := namada.ValidatorMetaData{}
	err = borsh.Deserialize(&metadata, response.Response.Value)
	if err != nil {
		return nil, fmt.Errorf("unmarshal validator metadata: %w", err)
	}
	if metadata.Metadata != nil && metadata.Metadata.Name != nil {
		info.Moniker = *metadata.Metadata.Name
	}

	return &info, nil
}
