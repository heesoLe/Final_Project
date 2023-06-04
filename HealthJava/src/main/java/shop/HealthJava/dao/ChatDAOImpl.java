package shop.HealthJava.dao;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.annotation.PostConstruct;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import shop.HealthJava.vo.ChatRoomVO;

@Repository
public class ChatDAOImpl implements ChatDAO {

    @Autowired
    private SqlSession sqlSession;

    // ChatRoomVO createChatRoomVO(String name) method removed
    
    @Override
    public ChatRoomVO findChatRoomById(String roomId) {
        return chatRoomVOMap.get(roomId);
    }

    // List<ChatRoomVO> findAllRooms() method removed
    
    private Map<String, ChatRoomVO> chatRoomVOMap;

    @PostConstruct
    private void init() {
        chatRoomVOMap = new LinkedHashMap<>();
    }

    public List<ChatRoomVO> getAllChatRooms() {
        List<ChatRoomVO> result = new ArrayList<>(chatRoomVOMap.values());
        Collections.reverse(result);
        return result;
    }

    public void saveChatRoom(ChatRoomVO chatRoom) {
        // Generate a unique room ID (assuming it's not already set)
        if (chatRoom.getRoomId() == null) {
            chatRoom.setRoomId(UUID.randomUUID().toString());
            this.sqlSession.insert("saveChatRoom", chatRoom);
        }
        
        
        // Add the chat room to the map
        chatRoomVOMap.put(chatRoom.getRoomId(), chatRoom);
    }
	
}
