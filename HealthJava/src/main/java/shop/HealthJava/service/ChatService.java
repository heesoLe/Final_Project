package shop.HealthJava.service;

import java.util.List;

import shop.HealthJava.vo.ChatRoomVO;

public interface ChatService {

	ChatRoomVO createChatRoomVO(String name); // 채팅방 생성

	ChatRoomVO findRoomById(String roomId); // 생성된 채팅방 들어가기

	List<ChatRoomVO> findAllRooms(); // 채팅방 목록
	
}
