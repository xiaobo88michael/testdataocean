package main

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const TypeMsgPaySign = "pay_sign"

var _ sdk.Msg = &MsgPaySign{}

func NewMsgPaySign(creator string, videoId uint64, receivedSizeMB uint64, timestamp uint64, level uint64, sn uint64 ) *MsgPaySign {
	return &MsgPaySign{
		Creator:        creator,
		VideoId:        videoId,
		ReceivedSizeMB: receivedSizeMB,
		Timestamp:      timestamp,
		Sn: sn,
		Level: level,
	}
}

func (msg *MsgPlayVideo) Route() string {
	return "dataocean"
}



func (msg *MsgPaySign) Type() string {
	return TypeMsgPaySign
}

func (msg *MsgPaySign) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}


func (msg *MsgPaySign) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
