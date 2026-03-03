package com.yours.app.ui.messaging

import android.view.MotionEvent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.pointerInteropFilter
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.yours.app.identity.Contact
import com.yours.app.messaging.*
import com.yours.app.ui.theme.YoursColors
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

/**
 * Thread List Screen - Shows all conversations.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreadListScreen(
    threads: List<MessageThread>,
    onThreadClick: (MessageThread) -> Unit,
    onNewMessage: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Messages") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.Default.ArrowBack,
                            contentDescription = "Back"
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = YoursColors.Background
                )
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = onNewMessage,
                containerColor = YoursColors.Primary
            ) {
                Icon(
                    imageVector = Icons.Default.Edit,
                    contentDescription = "New message",
                    tint = YoursColors.OnPrimary
                )
            }
        }
    ) { padding ->
        if (threads.isEmpty()) {
            // Empty state
            Box(
                modifier = modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        imageVector = Icons.Default.Forum,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = YoursColors.OnBackgroundMuted
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "No messages yet",
                        style = MaterialTheme.typography.titleMedium,
                        color = YoursColors.OnBackgroundMuted
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Start a conversation with a contact",
                        style = MaterialTheme.typography.bodyMedium,
                        color = YoursColors.OnBackgroundMuted
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = modifier
                    .fillMaxSize()
                    .padding(padding),
                contentPadding = PaddingValues(vertical = 8.dp)
            ) {
                items(threads, key = { it.contactId }) { thread ->
                    ThreadItem(
                        thread = thread,
                        onClick = { onThreadClick(thread) }
                    )
                }
            }
        }
    }
}

/**
 * Single thread item in the list.
 */
@Composable
private fun ThreadItem(
    thread: MessageThread,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Avatar
        Box(
            modifier = Modifier
                .size(48.dp)
                .clip(CircleShape)
                .background(YoursColors.Primary),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = thread.contactPetname.firstOrNull()?.uppercase() ?: "?",
                style = MaterialTheme.typography.titleMedium,
                color = YoursColors.OnPrimary,
                fontWeight = FontWeight.Bold
            )
        }

        Spacer(modifier = Modifier.width(12.dp))

        // Content
        Column(modifier = Modifier.weight(1f)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = thread.contactPetname,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = if (thread.unreadCount > 0) FontWeight.Bold else FontWeight.Normal,
                    color = YoursColors.OnBackground
                )
                Text(
                    text = formatTimestamp(thread.lastMessageTime),
                    style = MaterialTheme.typography.bodySmall,
                    color = YoursColors.OnBackgroundMuted
                )
            }

            Spacer(modifier = Modifier.height(4.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = thread.lastMessagePreview.ifEmpty { "No messages" },
                    style = MaterialTheme.typography.bodyMedium,
                    color = YoursColors.OnBackgroundMuted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )

                if (thread.unreadCount > 0) {
                    Spacer(modifier = Modifier.width(8.dp))
                    Box(
                        modifier = Modifier
                            .clip(CircleShape)
                            .background(YoursColors.Primary)
                            .padding(horizontal = 8.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = thread.unreadCount.toString(),
                            style = MaterialTheme.typography.labelSmall,
                            color = YoursColors.OnPrimary
                        )
                    }
                }
            }
        }
    }
}

/**
 * Conversation Screen - Shows messages with a contact.
 *
 * SECURITY: This screen collects entropy from touch events to strengthen
 * key exchange. Even if the system RNG is compromised, user touch patterns
 * provide unpredictable entropy for session establishment.
 *
 * @param contact The contact for this conversation
 * @param messages List of messages in the conversation
 * @param onSendMessage Called when user sends a message
 * @param onBack Called when user navigates back
 * @param onTouchEntropy Optional callback to collect touch entropy for hedged key exchange
 * @param onKeyboardEntropy Optional callback to collect keyboard timing entropy
 * @param anonymityLevel Current anonymity level (based on available relays)
 * @param isSending Whether a message is currently being sent
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun ConversationScreen(
    contact: Contact,
    messages: List<Message>,
    onSendMessage: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onTouchEntropy: ((MotionEvent) -> Unit)? = null,
    onKeyboardEntropy: (() -> Unit)? = null,
    anonymityLevel: AnonymityLevel = AnonymityLevel.FULL,
    isSending: Boolean = false
) {
    var inputText by remember { mutableStateOf("") }
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()

    // Scroll to bottom when new messages arrive
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    // Collect touch entropy from the entire screen
    val entropyModifier = if (onTouchEntropy != null) {
        Modifier.pointerInteropFilter { event ->
            onTouchEntropy(event)
            false // Don't consume the event
        }
    } else {
        Modifier
    }

    Scaffold(
        modifier = entropyModifier,
        topBar = {
            ConversationTopBar(
                contactName = contact.petname,
                anonymityLevel = anonymityLevel,
                onBack = onBack
            )
        },
        bottomBar = {
            MessageInput(
                text = inputText,
                onTextChange = { newText ->
                    inputText = newText
                    // Collect keyboard entropy on each keystroke
                    onKeyboardEntropy?.invoke()
                },
                onSend = {
                    if (inputText.isNotBlank() && !isSending) {
                        onSendMessage(inputText)
                        inputText = ""
                    }
                },
                isSending = isSending
            )
        }
    ) { padding ->
        if (messages.isEmpty()) {
            Box(
                modifier = modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        imageVector = Icons.Default.Lock,
                        contentDescription = null,
                        modifier = Modifier.size(48.dp),
                        tint = YoursColors.Success
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "End-to-end encrypted",
                        style = MaterialTheme.typography.titleSmall,
                        color = YoursColors.Success
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Messages are encrypted with Double Ratchet\nand routed through onion layers",
                        style = MaterialTheme.typography.bodySmall,
                        color = YoursColors.OnBackgroundMuted,
                        textAlign = TextAlign.Center
                    )

                    // Show anonymity level indicator
                    Spacer(modifier = Modifier.height(16.dp))
                    AnonymityIndicator(level = anonymityLevel)
                }
            }
        } else {
            LazyColumn(
                modifier = modifier
                    .fillMaxSize()
                    .padding(padding),
                state = listState,
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(messages, key = { it.id }) { message ->
                    MessageBubble(message = message)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConversationTopBar(
    contactName: String,
    anonymityLevel: AnonymityLevel = AnonymityLevel.FULL,
    onBack: () -> Unit
) {
    val (statusText, statusColor) = when (anonymityLevel) {
        AnonymityLevel.FULL -> "Encrypted + Anonymous" to YoursColors.Success
        AnonymityLevel.REDUCED -> "Encrypted (reduced anonymity)" to YoursColors.Warning
        AnonymityLevel.MINIMAL -> "Encrypted (minimal anonymity)" to YoursColors.Warning
        AnonymityLevel.NONE -> "Encrypted (direct)" to YoursColors.Error
    }

    TopAppBar(
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(YoursColors.Primary),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = contactName.firstOrNull()?.uppercase() ?: "?",
                        style = MaterialTheme.typography.titleSmall,
                        color = YoursColors.OnPrimary,
                        fontWeight = FontWeight.Bold
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text(
                        text = contactName,
                        style = MaterialTheme.typography.titleMedium
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = if (anonymityLevel == AnonymityLevel.FULL)
                                Icons.Default.Lock else Icons.Default.Warning,
                            contentDescription = null,
                            modifier = Modifier.size(12.dp),
                            tint = statusColor
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = statusText,
                            style = MaterialTheme.typography.labelSmall,
                            color = statusColor
                        )
                    }
                }
            }
        },
        navigationIcon = {
            IconButton(onClick = onBack) {
                Icon(
                    imageVector = Icons.Default.ArrowBack,
                    contentDescription = "Back"
                )
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = YoursColors.Background
        )
    )
}

/**
 * Message bubble component.
 */
@Composable
private fun MessageBubble(message: Message) {
    val isOutgoing = message.direction == MessageDirection.OUTGOING
    val alignment = if (isOutgoing) Alignment.End else Alignment.Start
    val bubbleColor = if (isOutgoing) YoursColors.Primary else YoursColors.Surface
    val textColor = if (isOutgoing) YoursColors.OnPrimary else YoursColors.OnSurface

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = alignment
    ) {
        Box(
            modifier = Modifier
                .widthIn(max = 280.dp)
                .clip(
                    RoundedCornerShape(
                        topStart = 16.dp,
                        topEnd = 16.dp,
                        bottomStart = if (isOutgoing) 16.dp else 4.dp,
                        bottomEnd = if (isOutgoing) 4.dp else 16.dp
                    )
                )
                .background(bubbleColor)
                .padding(horizontal = 12.dp, vertical = 8.dp)
        ) {
            Text(
                text = message.text,
                style = MaterialTheme.typography.bodyMedium,
                color = textColor
            )
        }

        Spacer(modifier = Modifier.height(2.dp))

        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = if (isOutgoing) Arrangement.End else Arrangement.Start
        ) {
            Text(
                text = formatMessageTime(message.timestamp),
                style = MaterialTheme.typography.labelSmall,
                color = YoursColors.OnBackgroundMuted
            )

            if (isOutgoing) {
                Spacer(modifier = Modifier.width(4.dp))
                DeliveryIndicator(status = message.status)
            }
        }
    }
}

/**
 * Message delivery status indicator.
 */
@Composable
private fun DeliveryIndicator(status: MessageStatus) {
    val (icon, color) = when (status) {
        MessageStatus.PENDING -> Icons.Default.Schedule to YoursColors.OnBackgroundMuted
        MessageStatus.SENT -> Icons.Default.Done to YoursColors.OnBackgroundMuted
        MessageStatus.DELIVERED -> Icons.Default.DoneAll to YoursColors.Success
        MessageStatus.READ -> Icons.Default.DoneAll to YoursColors.Primary
        MessageStatus.FAILED -> Icons.Default.Error to YoursColors.Error
    }

    Icon(
        imageVector = icon,
        contentDescription = status.name,
        modifier = Modifier.size(14.dp),
        tint = color
    )
}

/**
 * Message input field.
 */
@Composable
private fun MessageInput(
    text: String,
    onTextChange: (String) -> Unit,
    onSend: () -> Unit,
    isSending: Boolean = false
) {
    Surface(
        tonalElevation = 2.dp,
        shadowElevation = 4.dp
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = text,
                onValueChange = onTextChange,
                placeholder = { Text("Message") },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(24.dp),
                maxLines = 4,
                enabled = !isSending,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = YoursColors.Primary,
                    unfocusedBorderColor = YoursColors.Surface
                )
            )

            Spacer(modifier = Modifier.width(8.dp))

            if (isSending) {
                CircularProgressIndicator(
                    modifier = Modifier.size(24.dp),
                    strokeWidth = 2.dp,
                    color = YoursColors.Primary
                )
            } else {
                IconButton(
                    onClick = onSend,
                    enabled = text.isNotBlank()
                ) {
                    Icon(
                        imageVector = Icons.Default.Send,
                        contentDescription = "Send",
                        tint = if (text.isNotBlank()) YoursColors.Primary else YoursColors.OnBackgroundMuted
                    )
                }
            }
        }
    }
}

/**
 * Anonymity level indicator component.
 */
@Composable
private fun AnonymityIndicator(level: AnonymityLevel) {
    val (icon, color, text) = when (level) {
        AnonymityLevel.FULL -> Triple(
            Icons.Default.Shield,
            YoursColors.Success,
            "Full anonymity (3+ relays)"
        )
        AnonymityLevel.REDUCED -> Triple(
            Icons.Default.Warning,
            YoursColors.Warning,
            "Reduced anonymity (2 relays)"
        )
        AnonymityLevel.MINIMAL -> Triple(
            Icons.Default.Warning,
            YoursColors.Warning,
            "Minimal anonymity (1 relay)"
        )
        AnonymityLevel.NONE -> Triple(
            Icons.Default.Error,
            YoursColors.Error,
            "No anonymity (direct mode)"
        )
    }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(color.copy(alpha = 0.1f))
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            modifier = Modifier.size(16.dp),
            tint = color
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = color
        )
    }
}

/**
 * Contact picker for new message.
 */
@Composable
fun ContactPickerScreen(
    contacts: List<Contact>,
    onContactSelected: (Contact) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = { Text("New Message") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, "Back")
                    }
                }
            )
        }
    ) { padding ->
        if (contacts.isEmpty()) {
            Box(
                modifier = modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        imageVector = Icons.Default.PersonAdd,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = YoursColors.OnBackgroundMuted
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "No contacts yet",
                        style = MaterialTheme.typography.titleMedium,
                        color = YoursColors.OnBackgroundMuted
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Add contacts by scanning their QR code",
                        style = MaterialTheme.typography.bodyMedium,
                        color = YoursColors.OnBackgroundMuted
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = modifier
                    .fillMaxSize()
                    .padding(padding),
                contentPadding = PaddingValues(vertical = 8.dp)
            ) {
                items(contacts, key = { it.id }) { contact ->
                    ContactItem(
                        contact = contact,
                        onClick = { onContactSelected(contact) }
                    )
                }
            }
        }
    }
}

@Composable
private fun ContactItem(
    contact: Contact,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(48.dp)
                .clip(CircleShape)
                .background(YoursColors.Primary),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = contact.initial,
                style = MaterialTheme.typography.titleMedium,
                color = YoursColors.OnPrimary,
                fontWeight = FontWeight.Bold
            )
        }

        Spacer(modifier = Modifier.width(12.dp))

        Column {
            Text(
                text = contact.petname,
                style = MaterialTheme.typography.titleSmall,
                color = YoursColors.OnBackground
            )
            Text(
                text = contact.trustLevel.name.lowercase()
                    .replaceFirstChar { it.uppercase() },
                style = MaterialTheme.typography.bodySmall,
                color = YoursColors.OnBackgroundMuted
            )
        }
    }
}

// Utility functions

private fun formatTimestamp(timestamp: Long): String {
    if (timestamp == 0L) return ""

    val now = System.currentTimeMillis()
    val diff = now - timestamp

    return when {
        diff < 60_000 -> "Now"
        diff < 3600_000 -> "${diff / 60_000}m"
        diff < 86400_000 -> "${diff / 3600_000}h"
        diff < 604800_000 -> "${diff / 86400_000}d"
        else -> SimpleDateFormat("MMM d", Locale.getDefault()).format(Date(timestamp))
    }
}

private fun formatMessageTime(timestamp: Long): String {
    return SimpleDateFormat("h:mm a", Locale.getDefault()).format(Date(timestamp))
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SmallTopAppBar(
    title: @Composable () -> Unit,
    navigationIcon: @Composable () -> Unit
) {
    TopAppBar(
        title = title,
        navigationIcon = navigationIcon,
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = YoursColors.Background
        )
    )
}
