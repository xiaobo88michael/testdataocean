package main

import (
	"context"
	"cosmossdk.io/simapp"
	"encoding/hex"
	"strings"

	//"github.com/cosmos/cosmos-sdk/client"

	//"cosmossdk.io/simapp/simd/cmd"
	//"github.com/cosmos/cosmos-sdk/client"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"

	"encoding/json"
	//"github.com/cosmos/cosmos-sdk/client"
	//tmproto "github.com/tendermint/tendermint/proto/tendermint/types"

	//"github.com/cosmos/cosmos-sdk/client"

	"github.com/cosmos/cosmos-sdk/client/tx"
	xauthsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"

	"fmt"
	dbm "github.com/cosmos/cosmos-db"
	codeTypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	"github.com/cosmos/cosmos-sdk/testutil/testdata"
	"github.com/cosmos/cosmos-sdk/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/tendermint/tendermint/libs/log"
	//xauthsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	"os"
)

type addmsg struct {
	fromaddress string      `json:"from_address"`
	toaddress   string      `json:"to_address"`
	amount      types.Coins `json:"amount"`
}

func main() {
	db := dbm.NewMemDB()
	logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout))
	app1 := simapp.NewSimApp(logger, db, nil, true, simtestutil.NewAppOptionsWithFlagHome(simapp.DefaultNodeHome))

	ctx := app1.NewContext(true, tmproto.Header{Height: app1.LastBlockHeight()})

	//paySign := NewMsgPaySign("1",1, 1,1234)

	//fmt.Println("paySign:", paySign)
	fmt.Println("ctx:", ctx)
	txConfig := app1.TxConfig()
	txBuilder := app1.TxConfig().NewTxBuilder()
	signModeHandle := app1.TxConfig().SignModeHandler()
	//ctx, err := client.GetClientTxContext(cmd.NewRootCmd())

	//fmt.Println("txbuilder:", txBuilder)
	priv1, _, addr1 := testdata.KeyTestPubAddr()
	priv2, _, addr2 := testdata.KeyTestPubAddr()
	priv3, _, addr3 := testdata.KeyTestPubAddr()

	fmt.Println("priv1, addr1:", priv1, addr1)
	fmt.Println("priv2, addr2:", priv2, addr2)
	fmt.Println("priv3, addr3:", priv3, addr3)
	pri := priv1.String()
	fmt.Println("privstring:", pri)
	//fmt.Println("privpriv:", pri.(cryptotypes.PrivKey))
	fmt.Println("priv1.bytes:", priv1.Bytes())
	fmt.Println("string(bytes):", string(priv1.Bytes()))
	fmt.Println("addstring:", addr1.String())
	//msg1 := banktypes.NewMsgSend(addr1, addr3, types.NewCoins(types.NewInt64Coin("atom", 12)))
	//msg2 := banktypes.NewMsgSend(addr2, addr3, types.NewCoins(types.NewInt64Coin("atom", 34)))
	msg1 := NewMsgPaySign(addr1.String(), 1, 20, 16384, 4, 1)
	any, errNewAny := codeTypes.NewAnyWithValue(msg1)
	if errNewAny != nil {
		fmt.Println("errNewAny:", errNewAny)
	}
	fmt.Println("url:", any.TypeUrl)
	//fmt.Println("rout:",msg1.Route())
	fmt.Println("type:", msg1.Type())
	fmt.Println("string:", msg1.String())
	fmt.Println("msg1:", msg1)
	//fmt.Println("msg2:", msg2)
	err := txBuilder.SetMsgs(msg1)

	addr, err := sdk.AccAddressFromBech32(addr1.String())
	fmt.Println("addr:", addr)

	if err != nil {
		return
	}
	getTx := txBuilder.GetTx()
	fmt.Println("getTx:", getTx)
	//accouts := app1.AccountKeeper.GetAllAccounts(ctx)
	//fmt.Println("accounts:", accouts)
	//txBuilder.SetGasLimit(20000)
	//account := authkeeper.AccountKeeper{}.GetAccount(ctx,addr1)
	privs := []cryptotypes.PrivKey{priv1}
	accNums := []uint64{0, 1}
	accSeqs := []uint64{0, 1}
	fmt.Println("accNums:", accNums)
	fmt.Println("accSeqs:", accSeqs)

	var sigsV2 []signing.SignatureV2
	for i, priv := range privs {
		sigV2 := signing.SignatureV2{
			PubKey: priv.PubKey(),
			Data: &signing.SingleSignatureData{
				SignMode:  app1.TxConfig().SignModeHandler().DefaultMode(),
				Signature: nil,
			},
			Sequence: accSeqs[i],
		}

		sigsV2 = append(sigsV2, sigV2)
	}

	errSet := txBuilder.SetSignatures(sigsV2...)
	if errSet != nil {
		return
	}
	fmt.Println("signv2:", sigsV2)
	fmt.Println("sigsv2data:", sigsV2[0].Data)

	sigsV2 = []signing.SignatureV2{}
	for _, priv := range privs {
		signerData := xauthsigning.SignerData{
			Address: sdk.AccAddress(priv.PubKey().Bytes()).String(),
			ChainID: "test-chain-1",
		}
		sigV2, err := tx.SignWithPrivKey(
			nil, txConfig.SignModeHandler().DefaultMode(), signerData, //nolint:staticcheck
			txBuilder, priv, txConfig)
		if err != nil {
			return
		}

		sigsV2 = append(sigsV2, sigV2)
	}
	err = txBuilder.SetSignatures(sigsV2...)
	if err != nil {
		return
	}
	fmt.Println("sigsv22:", sigsV2)
	fmt.Println("tx:", txBuilder.GetTx())

	signers := txBuilder.GetTx().GetSigners()
	pubkeys, err := txBuilder.GetTx().GetPubKeys()
	signatures, err := txBuilder.GetTx().GetSignaturesV2()
	//msgs:=txBuilder.GetTx().GetMsgs()
	//fmt.Println("msgs:", msgs)
	fmt.Println("account:", app1.AccountKeeper.GetAllAccounts(ctx))
	fmt.Println("signers:", signers)
	fmt.Println("pubkeys:", pubkeys)
	fmt.Println("signatures:", signatures)
	fmt.Println("data:", signatures[0].Data)
	fmt.Println("sequence:", signatures[0].Sequence)
	fmt.Println("pubkey:", signatures[0].PubKey)
	sigAddr := sdk.AccAddress(signatures[0].PubKey.Address())
	fmt.Println("signAddr:", sigAddr)

	//client.AccountRetriever().GetAccountNumberSequence()
	//accnum := app1.AccountKeeper.GetAccount(ctx,sigAddr).GetAccountNumber()
	////accnum := account.GetAccountNumber()
	//accseq := app1.AccountKeeper.GetAccount(ctx,sigAddr).GetSequence()
	//fmt.Println("account:", accnum)

	//accNum, accSeq, err := clientCtx.AccountRetriever.GetAccountNumberSequence(clientCtx, sigAddr)
	//fmt.Println("accNum:", accNum)
	//fmt.Println("accSeq:", accSeq)
	signingData := xauthsigning.SignerData{
		Address:       sigAddr.String(),
		ChainID:       "test-chain-1",
		AccountNumber: 0,
		Sequence:      0,
		PubKey:        signatures[0].PubKey,
	}
	err = xauthsigning.VerifySignature(context.Background(), signatures[0].PubKey, signingData, signatures[0].Data, signModeHandle, txBuilder.GetTx())
	fmt.Println("err:", err)
	if err != nil {
		fmt.Println("err:", err)
	}
	txBytes, err := txConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		return
	}
	txBase64 := hex.EncodeToString(txBytes)
	//var a string
	//json.Unmarshal(txBytes, a)
	//fmt.Println("a:", a)
	fmt.Println("txbytes:", string(txBytes))
	fmt.Println("txBase64:", txBase64)
	txJSONBytes, err := txConfig.TxJSONEncoder()(txBuilder.GetTx())

	if err != nil {
		fmt.Println("err:", err)
	}
	txJSON := string(txJSONBytes)
	fmt.Println("txjson:", txJSON)

	txJsonDecoder, err := txConfig.TxJSONDecoder()(txJSONBytes)
	fmt.Println("tx:", txJsonDecoder)

	fmt.Println("getmsgs:", txJsonDecoder.GetMsgs())
	msgstring := txJsonDecoder.GetMsgs()[0].String()
	fmt.Println("msgs:", msgstring)
	fmt.Println("msgbyte:", []byte(msgstring))
	from, to, amount := getDecryptMsg(msgstring)
	fmt.Println("from:", from)
	fmt.Println("to:", to)
	fmt.Println("amount:", amount)
	var addm addmsg
	json.Unmarshal([]byte(msgstring), addm)
	fmt.Println("addm:", addm)
	fmt.Println("addm:", addm.amount)

	pubkeynums, err := txJsonDecoder.(xauthsigning.SigVerifiableTx).GetPubKeys()
	fmt.Println("pubkeys:", pubkeynums)
	fmt.Println("signsers:", txJsonDecoder.(xauthsigning.SigVerifiableTx).GetSigners())

	txby, err := txConfig.TxDecoder()(txBytes)
	fmt.Println("txby:", txby)

	txjson, err := txConfig.TxJSONEncoder()(txby)
	fmt.Println("txjson:", string(txjson))
	var m map[string]interface{}
	_ = json.Unmarshal(txjson, &m)
	fmt.Println("m:", m)

}

func getDecryptMsg(src string) (address string, videoId string, expire string) {
	strs := strings.Split(src, " ")
	address = strings.Split(strs[0], ":")[1]
	videoId = strings.Split(strs[1], ":")[1]
	expire = strings.Split(strs[2], ":")[1]
	return
}
