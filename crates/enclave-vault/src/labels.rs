//! What each command is doing, in words, for the bar the window shows
//! when one takes more than a moment ([`SHOW_AFTER`]): never a bare
//! "Working…". In English; the window translates (`cargo xtask i18n`
//! picks these up).

use enclave_ipc::Cmd;

/// How long a command runs before the bar says what it is doing.
pub const SHOW_AFTER: std::time::Duration = std::time::Duration::from_millis(700);

/// What `cmd` is doing, or `None` for what streams many times a second
/// (keystrokes, the microphone, a recording's frames) or what is never
/// slow and nobody waits for.
pub fn label(cmd: &Cmd) -> Option<&'static str> {
    use Cmd::*;
    Some(match cmd {
        Typing(..) | CallMic(_) | CallFrame(..) | RecordFrame(..) | RecordSound(_) | Stage(_)
        | Visible(_) | Reattach | LanChunks(..) | VideoMore(_) | TogglePick(_) | RevealWords(_)
        | CodeWordsEnglish(_) | PushToken(..) | LanServing(..) | LanFailed(..) => return None,
        Create(..) => "Setting up your account…",
        Select(_) => "Opening the conversation…",
        Send(..) | SendReply(..) => "Sending your message…",
        Accept(_) => "Accepting the request…",
        Decline(_) => "Removing the request…",
        Add(..) => "Sending your request…",
        Check(_) => "Saving that the codes match…",
        Privacy(_) => "Changing your privacy setting…",
        WordsSaved => "Saving that the words are written down…",
        CreateGroup(..) => "Creating the group…",
        LinkScan(_) => "Checking the new device's code…",
        LinkPick(_) => "Linking your new device…",
        ClaimUsername(_) => "Claiming your username…",
        RemoveDevice(_) => "Removing the device…",
        StartJoin => "Getting a code for this device…",
        CancelJoin => "Stopping the linking…",
        SendHistory(_) => "Sending your history to the new device…",
        StopRecovery => "Stopping the change to your account…",
        ApproveRecovery => "Approving the change to your account…",
        Meet(true) => "Making your in-person code…",
        Meet(false) => "Closing the in-person check…",
        MeetScan(_) => "Checking their in-person code…",
        MeetConfirm => "Checking you in person…",
        React(..) => "Sending your reaction…",
        Edit(..) => "Sending your edit…",
        Delete(..) => "Deleting the message for everyone…",
        Timer(..) => "Changing the disappearing timer…",
        SendFile(..) | SendStaged(..) => "Sending your file…",
        SaveFile(..) => "Saving the file…",
        Search(_) => "Searching your messages…",
        AddMembers(..) => "Adding them to the group…",
        RemoveMember(..) => "Removing them from the group…",
        SetGroupAdmin(..) => "Changing who is an admin…",
        LeaveGroup(_) => "Leaving the group…",
        Unlock(_) | UnlockBiometric(..) => "Unlocking your profile…",
        Lock => "Locking Enclave…",
        SetPassphrase(_) => "Changing your Enclave PIN…",
        NewInvite(..) => "Making an invite link…",
        CancelInvites => "Cancelling your invite links…",
        NewGroupInvite(..) => "Making a group invite link…",
        CreatePoll(..) => "Sending your poll…",
        Vote(..) => "Sending your vote…",
        ClosePoll(..) => "Closing the poll…",
        SaveBackup(_) => "Making your backup…",
        Restore(..) => "Restoring your account…",
        GiveShares(..) => "Giving out your recovery shares…",
        RevealShare(_) => "Opening the recovery share…",
        Pin(..) => "Pinning the message…",
        ConvPrefs(..) => "Saving the conversation's settings…",
        Block(..) => "Blocking them…",
        ShareContact(..) => "Sharing the contact…",
        AddShared(..) => "Adding the shared contact…",
        ShareLocation(..) => "Sharing your location…",
        Report(..) => "Sending your report…",
        CreatePack(..) => "Making the sticker pack…",
        SendSticker(..) => "Sending the sticker…",
        AddPack(..) => "Adding the sticker pack…",
        LoadStickers => "Loading your stickers…",
        TypingSetting(_)
        | ReceiptsSetting(_)
        | LinkPreviewsSetting(_)
        | GifSearchSetting(_)
        | SetPreviews(_)
        | SetScreenSecurity(_)
        | Theme(_) => "Saving your setting…",
        ChangeWords => "Making your new recovery words…",
        PlayClip(..) => "Opening the clip…",
        BackupRoute(_) => "Changing the backup route…",
        SetBridges(..) => "Saving your Tor bridges…",
        SetOnRecord(..) => "Changing who keeps a record…",
        SetAnnouncementOnly(..) => "Changing who can post…",
        NewFolder(_) => "Making the folder…",
        DeleteFolder(_) => "Deleting the folder…",
        InFolder(..) => "Moving the conversation…",
        ShowFolder(_) => "Opening the folder…",
        OpenLink(_) => "Opening the link…",
        Forward(..) => "Forwarding the message…",
        OpenFile(..) => "Opening the file…",
        SendViewOnce(..) => "Sending your view-once file…",
        OpenViewOnce(..) => "Opening the view-once file…",
        AllFiles => "Loading every photo and file…",
        RemovePack(_) => "Removing the sticker pack…",
        SetName(_) => "Saving your name…",
        SetAbout(_) => "Saving your about…",
        SetPhoto(..) => "Saving your photo…",
        PreviewPack(..) => "Opening the sticker pack…",
        GifSearch(_) => "Searching for GIFs…",
        SendGif(..) => "Sending the GIF…",
        PostStory(..) => "Posting your story…",
        DeleteStory(_) => "Deleting your story…",
        OpenStory(_) => "Opening the story…",
        StoryHidden(..) => "Saving who sees your stories…",
        RecordStart(..) => "Starting the recording…",
        RecordEnd(_) => "Sending your recording…",
        RecordCancel => "Throwing the recording away…",
        StopVideo => "Stopping the video…",
        WordsLanguage(_) => "Changing the words' language…",
        ReleaseShare(_) => "Sending the recovery share…",
        AskShares => "Asking your friends for your recovery…",
        DeleteAccount => "Deleting your account…",
        EraseDevice => "Erasing this device…",
        SetRootPin(_) => "Setting your recovery PIN…",
        UnlockRoot(_) => "Unlocking your recovery…",
        SecureAccount => "Securing your account…",
        SetAppLock(_) => "Setting your app PIN…",
        SetLockTimeout(_) => "Saving when Enclave locks…",
        ServerBackup(_) => "Changing your server backup…",
        CheckBackup(..) => "Checking your backup…",
        RestoreFromServer(_) => "Restoring your account from the server…",
        SetEmergencyPin(_) => "Setting your emergency PIN…",
        PickServer(_) => "Choosing your server…",
        MoveHome(_) => "Moving to the new server…",
        VoteGroupHost(..) => "Sending your vote for the group's server…",
        SetBiometric(_) => "Changing fingerprint or face unlock…",
        Wake => "Checking for new messages…",
        VerifyBuild(_) => "Checking this build…",
        CheckUpdates => "Checking for updates…",
        StartCall(..) | StartGroupCall(..) => "Starting the call…",
        AnswerCall | AnswerCallDirect => "Answering the call…",
        DeclineCall => "Declining the call…",
        EndCall => "Ending the call…",
        CallMute(_) => "Changing your microphone…",
        CallCamera(_) => "Changing your camera…",
        JoinGroupCall(..) => "Joining the call…",
        CallHand(_) => "Raising your hand…",
        CallReact(_) => "Sending your reaction…",
        CreateCallLink(..) => "Making a call link…",
        AdmitToCall(_) => "Letting them in…",
        RefuseFromCall(_) => "Turning them away…",
        CallScreen(_) => "Changing what you share…",
        PlayVoice(..) => "Opening the voice note…",
        TranscriptionModel(true) => "Downloading the transcription model…",
        TranscriptionModel(false) => "Deleting the transcription model…",
        Transcribe(..) => "Transcribing the voice note…",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_commands_say_what_they_do() {
        assert_eq!(
            label(&Cmd::Add("x".into(), String::new())),
            Some("Sending your request…")
        );
        assert_eq!(label(&Cmd::LinkPick(0)), Some("Linking your new device…"));
        assert_eq!(label(&Cmd::Meet(true)), Some("Making your in-person code…"));
        assert_eq!(label(&Cmd::Typing("x".into(), true)), None);
    }
}
