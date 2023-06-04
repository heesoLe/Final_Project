<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<script src="https://code.jquery.com/jquery-3.6.4.js"></script> <!-- jquery CDN -->
<title>채팅 연습 폼</title>
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
	
	.modal {
		display: none;
		position: fixed;
		top: 60%;
		right: 13%;
	}
	
	.modal.show {
		display: block;
	}
	
	.modal_wrap {
		width: 370px;
		height: 680px;
		border-radius: 20px;
		background-color: rgba(247, 247, 247);
		position: absolute;
		top: 60%;
		left: 87.5%;
		transform: translateX(-50%) translateY(-50%);
		box-shadow: 0 0 25px 5px lightgray;
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
	
	.modal_title {
		width: 300px;
		height: 40px;
	}
	
	#modal_title {
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
	
	.modal_logo {
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
	            <img src="<%=request.getContextPath()%>/images/Chatt_logo.png" id="Chatt_logo" alt="로고">
	        </div>
	    </div>
    </div>
    <!-- 숨기는 영역 끝 -->
	<!-- 메신저 로고 -->
	    <div class="test">
	        <div class="chatt_logo" onclick="openModal();">
	            <img src="<%=request.getContextPath()%>/images/messenger_logo.png" id="messenger_logo" alt="로고">
	        </div>
	    </div>
	<!-- 메신저 로고 끝 -->
	<script>
	    // 채팅창 열기(세션값 없으면 안떠야하는데 뜸..)
		function openModal() {
		        window.open("/chatmodal", "chatmodal", 'top=245, left=1290, width=380, height=680, scrollbars=no, toolbar=no, location=no, resizable=no, status=no, menubar=no');
		}
		
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