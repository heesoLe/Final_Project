package shop.HealthJava.dao;

import java.util.List;

import shop.HealthJava.vo.ChatRoomVO;

public interface ChatDAO {

	List<ChatRoomVO> getAllChatRooms(); // 채팅방 목록

	ChatRoomVO findChatRoomById(String roomId); // 생성된 채팅방 들어가기

	void saveChatRoom(ChatRoomVO chatRoom); // 채팅방 생성
	
}
