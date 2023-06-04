package shop.HealthJava.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import shop.HealthJava.dao.ChatDAO;
import shop.HealthJava.vo.ChatRoomVO;

@Service
public class ChatServiceImpl implements ChatService {

	@Autowired
	private ChatDAO chatDao;

   @Override
    public ChatRoomVO createChatRoomVO(String name) { // 채팅방 생성
        ChatRoomVO chatRoom = new ChatRoomVO();
        chatRoom.setName(name);
        // Save the chat room to the database
        chatDao.saveChatRoom(chatRoom);
        return chatRoom;
    }

    @Override
    public ChatRoomVO findRoomById(String roomId) { // 생성된 채팅방 들어가기
        return chatDao.findChatRoomById(roomId);
    }

    @Override
    public List<ChatRoomVO> findAllRooms() { // 채팅방 목록 불러오기
        return chatDao.getAllChatRooms();
    }
	
}
