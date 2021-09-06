declare global {
  interface String {
    format(...replacements: string[]): string;
  }
}

String.prototype.format = function() {
  var args = arguments;
  return this.replace(/{(\d+)}/g, function(match, number) { 
    return typeof args[number] != 'undefined'
      ? args[number]
      : match
    ;
  });
};

export const strings = {
  signedUpEmailSubject: "Someone signed up with Digitr",
  signedUpEmailText: "{0} signed up with Digitr! \n School Name: {1}",
  passUsed: "Pass Used",
  passUsedText: "{0} is going to the {1}. This user has {2} passes left. (You have approved {3} passes to this user.)",
  passRequest: "Pass Request",
  passRequestText: "{0} would like to use a pass to go to the {1}. This user has {2} passes left. (You have approved {3} passes to this user.)",
  passRejected: "Pass Rejected",
  passRejectedText: "Your request to use a pass was rejected.",
  passDone: "Time's up",
  passDoneTextStudent: "Your pass time is over. Get back as soon as possible.",
  passDoneTextTeacher: "{0}'s pass time is over.",
  passApproved: "Pass Approved",
  passApprovedText: "Your request to go to the {0} was approved. You have {1} minutes. The timer starts now.",
  passBack: "Pass is done",
  passBackText: "{0} is back.",
  intervalDefault: "0 seconds",
  interval: "{0} minutes and {1} seconds",
  mvpDefault: "Nobody",
  mudDefault: "No where",
  csvStartingText: "User,Pass,Destination,Teacher,Minutes,Timestamp(EST),End Time(EST)\n"

}