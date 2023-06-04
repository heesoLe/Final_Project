<%@ page contentType="text/html; charset=UTF-8"%>
<!DOCTYPE html>
<html>
<head>
    <title>Chat Room</title>
    <!-- Bootstrap CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-gH2yIJqKdNHPEq0n4Mqa/HGKIhSkIHeL5AyhkYV8i59U5AR6csBvApHHNl/vI1Bx" crossorigin="anonymous">
    <!-- JavaScript CDN -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sockjs-client@1/dist/sockjs.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/stomp.js/2.3.3/stomp.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/js/bootstrap.bundle.min.js"
            integrity="sha384-A3rJD856KowSb7dwlZdYEkO39Gagi7vIsF0jrRAoQmDKKtQBHUuLZ9AsSv4jD4Xa"
            crossorigin="anonymous"></script>
<style type="text/css">
	/* 폰트 CSS */
	@font-face {
	   font-family: 'KIMM_Bold';
	   src:url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2212@1.0/KIMM_Bold.woff2') format('woff2');
	   font-weight: 700;
	   font-style: normal;
	}
	
	* {
		font-family: 'KIMM_Bold';
	}
	
	.container {
		overflow-x: hidden; /* 가로 스크롤 제거 */
	}
	
	#msg {
		height: 60px;
		width: 300px;
		background-color: rgba(242, 242, 243);
		border: none;
		border-radius: 10px;
		outline: none;
		position: fixed;
		bottom: 2%;
		left: 5%;
		z-index: 1;
	}
	
	#button-send {
		height: 60px;
		width: 50px;
		margin-left: 10px;
		background-color: rgba(242, 242, 243);
		color: gray;
		border: none;
		border-radius: 10px;
		position: fixed; /* 해당값 변경 */
		bottom: 2%;
		right: 3.5%;
	}
	
	/* 본인 */
	.message-sent {
    	overflow: hidden;
    	height: auto;
		width: 300px;
        background-color: rgba(178, 24, 72); /* 테마색 */
        color: white;
        border: none;
		border-radius: 10px;
		outline: none;
		margin: 0px;
		margin-top: 25px;
		position: relative;
		right: -30.5%;
		white-space: normal;
  		word-break: break-word;
  		font-size: 14px;
    }
    
    .message-time1 {
		font-size: 10px;
		font-weight: bold;
		color: gray;
		margin-top: 1px;
		margin-bottom: 15px;
		float: right;
	}
	
	/* 상대방 */
    .message-received {
    	overflow: hidden;
    	height: auto;
		width: 300px;
        background-color: rgba(242, 242, 242); /* 밝은 회색 */
        color: black;
        border: none;
		border-radius: 10px;
		outline: none;
		margin: 0px;
		margin-top: 25px;
		white-space: normal;
  		word-break: break-word;
  		font-size: 14px;
    }
    
    .message-time2 {
		font-size: 10px;
		font-weight: bold;
		color: gray;
		margin-top: 1px;
		margin-bottom: 15px;
		float: left;
	}
    
    .chat_title {
    	width: 100%;
		height: 60px;
		background-color: rgba(242, 242, 243);
    }
    
    #chat_title {
		font-size: 21px;
		position: relative;
		top: -33%;
		left: 33%;
	}
	
	.chat_text {
		height: 60px;
		width: 350px;
		background-color: rgba(242, 242, 243);
		border: none;
		border-radius: 10px;
		outline: none;
		position: fixed;
		bottom: 2%;
	}
	
	.chatt_logo {
		width: 35px;
		height: 35px;
		border-radius: 70%;
		overflow: hidden;
		position: relative;
		top: 20%;
		left: 22%;
	}
	
	#Chatt_logo {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}
	
	.chatt_logo2 {
		width: 100px;
		height: 100px;
		border-radius: 70%;
		overflow: hidden;
		margin-top: 5%;
		margin-bottom: 1%;
		margin-left: 36%;
	}
	
	#Chatt_logo2 {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}
	
	.chat_question {
    	width: 100%;
		height: 25px;
    }
    
    #chat_question {
		font-size: 18px;
		position: relative;
		left: 18%;
	}
	
	#comment {
		width: 8px;
		height: 8px;
		position: relative;
		left: 33%;
	}
	
	.chat_answer {
    	width: 100%;
		height: 40px;
    }
    
    #chat_answer {
		font-size: 12px;
		position: relative;
		left: 34%;
	}
	
	/* 메시지 출력부분 */
	#msgArea {
    	height: 350px;
    	overflow-y: auto;
	}

	#msgArea::-webkit-scrollbar {
		width: 0; /* 스크롤바의 너비를 0으로 설정하여 숨김 */
	}
	
	#msgArea::-webkit-scrollbar-track {
		background-color: transparent; /* 스크롤바 트랙 배경색 */
	}
	
	#msgArea::-webkit-scrollbar-thumb {
		background-color: #888; /* 스크롤바 색상 */
		border-radius: 0.25em; /* 스크롤바의 둥근 모서리 반경 */
	}
	
	#msgArea::-webkit-scrollbar-thumb:hover {
		/* background-color: #555; */ /* 마우스 호버 시 스크롤바 색상 */
	}
</style>
</head>
<body>
<div class="chat_title">
    <div class="chatt_logo">
        <img src="<%=request.getContextPath()%>/images/Chatt_logo.png" id="Chatt_logo" alt="로고">
    </div>
    <span id="chat_title">헬스자바 쇼핑몰</span>
</div>
<div class="chatt_logo2">
    <img src="<%=request.getContextPath()%>/images/Chatt_logo.png" id="Chatt_logo2" alt="로고">
</div>
<div class="chat_question">
    <span id="chat_question">헬스자바 쇼핑몰에 문의하기</span>
</div>
<div class="chat_answer">
    <img src="<%=request.getContextPath()%>/images/comment.png" id="comment" alt="반응">
    <span id="chat_answer">보통 수십 분 내 답변</span>
</div>
<div class="container" id="chat">
    <div class="col-6"></div>
    <div>
        <div id="msgArea" class="col"></div>
        <div class="col-6" id="chatDiv">
            <div class="chat_text">
                <input type="text" id="msg" placeholder="메시지를 입력해주세요.">
                <div class="input-group-append">
                    <button type="button" id="button-send">
                        <img src="<%=request.getContextPath()%>/images/right.png" alt="전송">
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    $(document).ready(function () {
        var roomName = '${room.name}';
        var roomId = '${room.roomId}';
        var username = '${session.session_id}';

        console.log(roomName + ", " + roomId + ", " + username);

        var sockJs = new SockJS("/stomp/chat");
        var stomp = Stomp.over(sockJs);

        stomp.connect({}, function () {
            console.log("STOMP 연결 완료");

            stomp.subscribe("/sub/chat/room/" + roomId, function (chat) {
                var content = JSON.parse(chat.body);
                var writer = content.writer;
                var message = content.message;
                var currentDate = new Date();
                var timestamp = currentDate.toLocaleString([], {
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                });

                var str = '';

                if (writer === username) {
                    str += "<div class='col-6'>";
                    str += "<div class='alert alert-secondary message-sent'>";
                    str += "<b>" + message + "</b>";
                    str += "</div></div>";
                    str += "<div class='message-time1'>" + timestamp + "</div>";
                } else {
                    str += "<div class='col-6'>";
                    str += "<div class='alert alert-warning message-received'>";
                    str += "<b>" + message + "</b>";
                    str += "</div></div>";
                    str += "<div class='message-time2'>" + timestamp + "</div>";
                }

                $("#msgArea").append(str);
            });

            stomp.send('/pub/chat/enter', {}, JSON.stringify({roomId: roomId, writer: username}));
        });

        function sendMessage() {
            var msg = $("#msg").val();
            var timestamp = new Date($.now()).toLocaleString();

            if (msg.trim() === '') {
                return;
            }

            console.log(username + ":" + msg);

            stomp.send('/pub/chat/message', {}, JSON.stringify({roomId: roomId, message: msg, writer: username}));

            $("#msg").val('');

            $("#msgArea").scrollTop($("#msgArea")[0].scrollHeight);

            setTimeout(function () {
                $("#msgArea").scrollTop($("#msgArea")[0].scrollHeight);
            }, 100);
        }

        $("#button-send").on("click", function (e) {
            sendMessage();
        });

        $("#msg").on("keydown", function (e) {
            if (e.keyCode === 13) {
                sendMessage();
            }
        });
    });

    window.addEventListener('beforeunload', function (e) {
        e.preventDefault();
        e.returnValue = '';
    });
    
    // 자식 창에서 부모 창 닫기
    function closeParentWindow() {
      if (window.opener && !window.opener.closed) {
        window.opener.close();
      }
    }
    
    // 자식 창이 열리면 부모 창 닫기
    window.onload = closeParentWindow;
</script>
</body>
</html>
