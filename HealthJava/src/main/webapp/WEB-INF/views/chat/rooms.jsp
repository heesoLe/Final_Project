<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Chat Page</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        /* 채팅 페이지 여는 CSS */
        .chatt_logo {
            width: 35px;
            height: 35px;
            border-radius: 70%;
            overflow: hidden;
            position: relative;
            top: 20%;
            left: 22%;
            cursor: pointer;
        }

        #Chatt_logo {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        .test {
        	display: none;
        }
        .location {
        	position: fixed;
        	bottom: 5%;
        	right: 3%;
        }
    </style>
</head>
<body>
	<h1>현재 생성된 채팅방 목록</h1>
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
    <!-- 숨긴 영역 -->
    <div class="test">
        <div class="chatt_logo" onclick="openCreateRoom();">
            <img src="<%=request.getContextPath()%>/images/Chatt_logo.png" id="Chatt_logo" alt="로고">
        </div>
    </div>
    <!-- 숨긴 영역 끝 -->
    <div class="location">
		<jsp:include page="./chatting.jsp"/>
	</div>
    <script>
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
            window.open(url, 'chatroom', 'top=10, left=10, width=370, height=660, scrollbars=no, toolbar=no, location=no, resizable=no, status=no, memubar=no');
        }

        function openPopup_chatroom(event, roomId, roomName) {
            event.preventDefault();
            var url = '/chat/room?roomId=' + roomId;
            window.open(url, 'chatroom', 'top=10, left=10, width=370, height=660, scrollbars=no, toolbar=no, location=no, resizable=no, status=no, memubar=no');
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