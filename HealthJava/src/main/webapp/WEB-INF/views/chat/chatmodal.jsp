<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<script src="https://code.jquery.com/jquery-3.6.4.js"></script> <!-- jquery CDN -->
<title></title>
<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/CSS/chatt.css" />
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
	
	.page_wrap {
		width: 370px;
		height: 680px;
		border-radius: 20px;
		background-color: rgba(247, 247, 247);
	}
	
	.m_head {
		height: 8%;
		background-color: rgba(247, 247, 247);
		padding: 10px;
		border-top-left-radius: 20px;
		border-top-right-radius: 20px;
		display: flex;
		justify-content: space-between;
	}
	
	.m_body {
		height: 82%;
		padding: 20px;
	}
	
	.m_footer {
		height: 10%;
		background-color: rgba(247, 247, 247);
		padding: 15px;
		border-bottom-left-radius: 20px;
		border-bottom-right-radius: 20px;
		display: flex;
		justify-content: end;
	}
	
	.page_title {
		width: 300px;
		height: 40px;
	}
	
	#page_title {
		font-size: 21px;
		position: relative;
		top: -68%;
		left: 17%;
	}
	
	.close_btn {
		cursor: pointer;
		position: relative;
		top: 28%;
		right: 2.5%;
	}
	
	.page_logo {
		width: 35px;
		height: 35px;
		border-radius: 70%;
		overflow: hidden;
		position: relative;
		top: 5%;
		left: 2.5%;
	}
	
	#chatt_logo {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}
	
	.m_body2 {
		width: 330px;
		height: 180px;
		background-color: white;
		border-radius: 20px;
		box-shadow: 0 0 10px 1px rgba(0,0,0,0.1);
	}
	
	.m_title {
		width: 100%;
		height: 100%;
	}
	
	.m_logo {
		width: 40px;
		height: 40px;
		border-radius: 70%;
		overflow: hidden;
		position: relative;
		top: 9%;
		left: 2.5%;
	}
	
	#chatt_logo2 {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}
	
	#m_title {
		font-size: 13px;
		position: relative;
		top: -10%;
		left: 17%;
	}
	
	.m_cont {
		width: 260px;
		font-size: 15px;
		position: relative;
		top: -79%;
		left: 17%;
	}
	
	.m_move {
		width: 290px;
		height: 60px;
		background-color: rgba(172, 24, 78);
		border-radius: 20px;
		position: relative;
		top: -70%;
		left: 6%;
		cursor: pointer;
	}
	
	#move_img {
		width: 30px;
		height: 30px;
		position: relative;
		top: 22%;
		left: 30%;
	}
	
	.move_text {
		width: 100px;
		position: relative;
		top: -24%;
		left: 41%;
	}
	
	#move_text {
		color: white;
	}
	
	#comment_img {
		width: 7px;
		heiht: 7px;
		position: relative;
		top: -70%;
		left: 35%;
	}
	
	.comment_text {
		width: 100px;
		position: relative;
		top: -79%;
		left: 39%;
	}
	
	#comment_text {
		font-size: 9px;
	}
	
	#messenger_img {
		position: relative;
		top: -68%;
		left: 37%;
	}
	
	.messenger_text {
		width: 100px;
		position: relative;
		top: -80%;
		left: 43%;
	}
	
	#messenger_text {
		font-size: 9px;
		color: gray;
	}
	#messenger_logo {
		cursor: pointer;
		width: 47px;
		height: 47px;
	}
	.hide {
		display: none;
	}
</style>
</head>
<body>
	<!-- 숨기는 영역 원본은 rooms.jsp -->
	<div class="hide">
		<c:if test="${session_id eq 'admin'}">
	        <div class="container">
	            <div>
	                <ul>
	                    <c:forEach items="${list}" var="room">
	                        <li>
	                            <a href="/chat/room?roomId=${room.roomId}"
	                               data-roomid="${room.roomId}"
	                               onclick="openPopup_chatroom(event, '${room.roomId}', '${room.name}');">
	                               ${room.name}
	                            </a>
	                        </li>
	                    </c:forEach>
	                </ul>
	            </div>
	        </div>
		</c:if>
	    <form id="createRoomForm" action="/chat/room" method="post">
	        <input type="text" name="name" class="form-control">
	        <button class="btn btn-secondary">개설하기</button>
	    </form>
	    <div class="test">
	        <div class="chatt_logo" onclick="openCreateRoom();">
	            <img src="../images/Chatt_logo.png" id="Chatt_logo" alt="로고">
	        </div>
	    </div>
    </div>
    <!-- 숨기는 영역 끝 -->
	<!-- 모달 -->
	<div class="page" id="page">
		<div class="page_wrap">
			<div class="m_head">
				<div class="page_title">
					<div class="page_logo">
						<img src="<%=request.getContextPath()%>/images/Chatt_logo.png" id="chatt_logo">
					</div>
					<span id="page_title">헬스자바 쇼핑몰</span>
				</div>
				<div class="close_btn" id="close_btn">
					
				</div>
			</div>
			<div class="m_body">
				<div class="m_body2">
					<div class="m_title">
						<div class="m_logo">
							<img src="<%=request.getContextPath()%>/images/Chatt_logo.png" id="chatt_logo2">
						</div>
						<span id="m_title">헬스자바 쇼핑몰</span>
					</div>
					<div class="m_cont">
						<span id="page_cont">고객님! 자바헬스에 오신 걸 환영합<br>니다. 무엇을 도와드릴까요?</span>
					</div>
					<div class="m_move" onclick="openCreateRoom();">
						<img src="<%=request.getContextPath()%>/images/move.png" id="move_img">
						<div class="move_text">
							<span id="move_text">새 문의하기</span>
						</div>
					</div>
					<img src="<%=request.getContextPath()%>/images/comment.png" id="comment_img">
					<div class="comment_text">
						<span id="comment_text">보통 수십 분 내 답변</span>
					</div>
					<img src="<%=request.getContextPath()%>/images/messenger.png" id="messenger_img">
					<div class="messenger_text">
						<span id="messenger_text">자바톡 이용중</span>
					</div>
				</div>
			</div>
			<div class="m_footer">
			</div>
		</div>
	</div>
	<!-- 모달 끝 -->
	<script>
	// 밑에서부터 채팅 관련
	$(document).ready(function () {
        $(".btn-create").on("click", function (e) {
            e.preventDefault();
            var name = $("input[name='name']").val();
            if (name == "")
                alert("Please write the name.");
            else
                $("#createRoomForm").submit();
        });
    });

    function openCreateRoom() {
        var sessionID = '<%= session.getAttribute("session_id") %>';
        
        if (sessionID == null || sessionID === "") {
        	alert("채팅 기능은 로그인 이후 사용 가능합니다!");
            return;
        }
        
        var roomName = sessionID + '님과의 채팅방';
        
        // Set the room name as the value of the input field
        $("input[name='name']").val(roomName);

        var createRoomForm = document.getElementById('createRoomForm');
        createRoomForm.submit();

        // Generate roomId
        var roomId = generateRoomId();

        // Open the chat room
        var url = '/chat/room?roomId=' + roomId;
        window.open(url, 'chatroom', 'top=245, left=1290, width=370, height=660, scrollbars=no, toolbar=no, location=no, resizable=no, status=no, memubar=no');
    }

    // a링크 클릭시 채팅방 열림
    function openPopup_chatroom(event, roomId, roomName) {
        event.preventDefault();
        var url = '/chat/room?roomId=' + roomId;
        window.open(url, 'chatroom', 'top=450, left=1200, width=370, height=660, scrollbars=no, toolbar=no, location=no, resizable=no, status=no, memubar=no');
    }

    function generateRoomId() {
        // Retrieve the roomId from the input field
        var roomId = $("input[name='name']").val();

        // Validate if roomId is not empty
        if (roomId.trim() === '') {
            // If roomId is empty, generate a new roomId
            var timestamp = new Date().getTime();
            roomId = 'ChattingRoom_' + timestamp;
        }

        return roomId;
    }
	</script>
</body>
</html>